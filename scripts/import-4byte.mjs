#!/usr/bin/env node
/**
 * Import the 4byte.directory function-selector database into Supabase.
 *
 * Source: ethereum-lists/4bytes — the bulk dataset behind 4byte.directory.
 * The site's API exposes the same rows paginated (~1.18M signatures,
 * 2026-10-17); the repo is one `git clone` instead of ~12k API pages.
 * Layout: `signatures/<hex>` — one file per 4-byte selector (no 0x),
 * contents are newline-separated text signatures (collisions included).
 *
 * Usage (from the repo root):
 *   node scripts/import-4byte.mjs [--dir <path>] [--limit N] [--dry-run]
 *
 * DATABASE_URL comes from the environment, or from pipeline-worker/.env
 * when it is not set. The table is created first from
 * migrations/0005_fourbyte.sql (inline fallback if the file is absent).
 *
 * Idempotent: INSERT ... ON CONFLICT DO NOTHING — safe to re-run/resume.
 * `--dry-run` parses and counts without touching the database.
 */
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const REPO_URL = "https://github.com/ethereum-lists/4bytes.git";
const BATCH_ROWS = 1000;
const LOG_EVERY_ROWS = 100_000;

const args = process.argv.slice(2);
function flagValue(name, fallback) {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : fallback;
}
const DATA_DIR = path.resolve(flagValue("--dir", "./4bytes"));
const LIMIT = flagValue("--limit", null) ? Number(flagValue("--limit", null)) : null;
const DRY_RUN = args.includes("--dry-run");

const log = (msg) => console.log(`[import-4byte] ${msg}`);

/** Fill missing env vars from pipeline-worker/.env (same layout the worker uses). */
function loadWorkerEnv() {
  if (process.env.DATABASE_URL) return;
  const envPath = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
    "pipeline-worker",
    ".env",
  );
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!m || process.env[m[1]] !== undefined) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    process.env[m[1]] = v;
  }
}

function ensureCheckout() {
  const sigDir = path.join(DATA_DIR, "signatures");
  if (fs.existsSync(sigDir) && fs.readdirSync(sigDir).length > 0) {
    log(`reusing existing checkout at ${DATA_DIR}`);
    return sigDir;
  }
  log(`cloning ${REPO_URL} (--depth 1) into ${DATA_DIR} ...`);
  try {
    execFileSync("git", ["clone", "--depth", "1", REPO_URL, DATA_DIR], { stdio: "inherit" });
  } catch {
    throw new Error(
      `git clone failed. Clone it yourself: git clone --depth 1 ${REPO_URL} ${DATA_DIR}`,
    );
  }
  if (!fs.existsSync(sigDir)) throw new Error(`checkout has no signatures/ dir: ${DATA_DIR}`);
  return sigDir;
}

const INLINE_SCHEMA = `
create table if not exists fourbyte_signatures (
  selector text not null,
  signature text not null,
  created_at timestamptz not null default now(),
  primary key (selector, signature)
);`;

async function loadSchema() {
  const sqlPath = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
    "migrations",
    "0005_fourbyte.sql",
  );
  if (fs.existsSync(sqlPath)) return fs.readFileSync(sqlPath, "utf8");
  log("migrations/0005_fourbyte.sql not found, using inline schema");
  return INLINE_SCHEMA;
}

/** Parse one selector file into [selector, signature] rows. */
async function parseFile(sigDir, file) {
  if (!/^[0-9a-f]{8}$/.test(file)) return { rows: [], skipped: 1 };
  const raw = await fsp.readFile(path.join(sigDir, file), "utf8");
  const selector = `0x${file}`;
  const seen = new Set();
  const rows = [];
  for (const line of raw.split("\n")) {
    const sig = line.trim();
    if (!sig || seen.has(sig)) continue;
    seen.add(sig);
    rows.push([selector, sig]);
  }
  return { rows, skipped: 0 };
}

async function flush(pool, batch) {
  if (batch.length === 0) return;
  const values = [];
  const params = [];
  batch.forEach(([selector, signature], i) => {
    values.push(`($${i * 2 + 1},$${i * 2 + 2})`);
    params.push(selector, signature);
  });
  await pool.query(
    `insert into fourbyte_signatures (selector, signature) values ${values.join(",")} on conflict do nothing`,
    params,
  );
}

async function main() {
  loadWorkerEnv();
  const sigDir = ensureCheckout();
  const files = (await fsp.readdir(sigDir)).sort();
  const wanted = LIMIT ? files.slice(0, LIMIT) : files;
  log(`parsing ${wanted.length} selector files from ${sigDir}${LIMIT ? ` (limit ${LIMIT})` : ""}`);

  let pool = null;
  let before = null;
  if (!DRY_RUN) {
    if (!process.env.DATABASE_URL) {
      throw new Error("DATABASE_URL is not set and pipeline-worker/.env has no entry.");
    }
    const { Pool } = await import("pg");
    pool = new Pool({
      connectionString: process.env.DATABASE_URL.replace(/([?&])sslmode=[^&]*(&|$)/, "$1").replace(/[?&]$/, ""),
      ssl: { rejectUnauthorized: false },
      max: 4,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 15_000,
      query_timeout: 60_000,
      allowExitOnIdle: true,
    });
    await pool.query(await loadSchema());
    before = Number((await pool.query("select count(*)::int as n from fourbyte_signatures")).rows[0].n);
    log(`table ready, rows before: ${before}`);
  }

  const started = Date.now();
  let batch = [];
  let rows = 0;
  let filesDone = 0;
  let skipped = 0;
  const sample = [];
  for (const file of wanted) {
    const { rows: fileRows, skipped: s } = await parseFile(sigDir, file);
    skipped += s;
    for (const row of fileRows) {
      if (sample.length < 5) sample.push(row);
      batch.push(row);
      rows++;
      if (batch.length >= BATCH_ROWS) {
        if (pool) await flush(pool, batch);
        batch = [];
      }
      if (rows % LOG_EVERY_ROWS === 0) {
        log(`${rows.toLocaleString()} rows parsed (${filesDone + 1} files, ${((Date.now() - started) / 1000).toFixed(0)}s)`);
      }
    }
    filesDone++;
  }
  if (pool) await flush(pool, batch);

  log(`done: ${filesDone.toLocaleString()} files, ${rows.toLocaleString()} rows parsed, ${skipped} skipped (non-selector names)`);
  if (DRY_RUN) {
    log("dry-run: no database writes. Sample rows:");
    for (const [sel, sig] of sample) log(`  ${sel}  ${sig}`);
    return;
  }
  const after = Number((await pool.query("select count(*)::int as n from fourbyte_signatures")).rows[0].n);
  log(`rows in table: ${before} -> ${after} (+${after - before})`);
  log("cross-check: 4byte.directory API count was 1,184,870 on 2026-10-17");
  await pool.end();
}

main().catch((err) => {
  console.error(`[import-4byte] FAILED: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
