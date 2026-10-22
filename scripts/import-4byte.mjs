#!/usr/bin/env node
/**
 * DEPRECATED (2026-10-22): bulk import is retired. 4byte resolution
 * is on-demand — bytecode analysis pulls just the selectors/topics
 * it encounters from the 4byte.directory API and caches only those
 * (src/lib/audit/fourbyte.ts, createOnDemandFourbyteLookup). Kept
 * for historical reference / a deliberate full re-seed only.
 *
 * Import the 4byte.directory function-selector + event-signature
 * databases into Supabase.
 *
 * Source: ethereum-lists/4bytes — the bulk dataset behind 4byte.directory.
 * The site's API exposes the same rows paginated (~1.18M function
 * signatures + ~278k event signatures, 2026-10-17); the repo is one
 * `git clone` instead of ~15k API pages. Layout:
 *   `signatures/<8-hex>` — one file per 4-byte selector (no 0x),
 *   `event-signatures/<64-hex>` — one file per 32-byte topic,
 * each file's contents are newline-separated text signatures
 * (collisions included).
 *
 * Usage (from the repo root):
 *   node scripts/import-4byte.mjs [--dir <path>] [--limit N] [--dry-run]
 *   [--only selectors|topics]
 *
 * DATABASE_URL comes from the environment, or from pipeline-worker/.env
 * when it is not set. The tables are created first from
 * migrations/0005_fourbyte.sql + migrations/0006_fourbyte_events.sql
 * (inline fallback if the files are absent).
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

const DATASETS = [
  { dir: "signatures", table: "fourbyte_signatures", keyLen: 8, label: "selectors" },
  { dir: "event-signatures", table: "fourbyte_event_signatures", keyLen: 64, label: "topics" },
];

const args = process.argv.slice(2);
function flagValue(name, fallback) {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : fallback;
}
const DATA_DIR = path.resolve(flagValue("--dir", "./4bytes"));
const LIMIT = flagValue("--limit", null) ? Number(flagValue("--limit", null)) : null;
const DRY_RUN = args.includes("--dry-run");
const ONLY = flagValue("--only", null); // "selectors" | "topics" | null

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
  const hasAny = DATASETS.some(
    (d) => fs.existsSync(path.join(DATA_DIR, d.dir)) && fs.readdirSync(path.join(DATA_DIR, d.dir)).length > 0,
  );
  if (hasAny) {
    log(`reusing existing checkout at ${DATA_DIR}`);
    return;
  }
  log(`cloning ${REPO_URL} (--depth 1) into ${DATA_DIR} ...`);
  try {
    execFileSync("git", ["clone", "--depth", "1", REPO_URL, DATA_DIR], { stdio: "inherit" });
  } catch {
    throw new Error(
      `git clone failed. Clone it yourself: git clone --depth 1 ${REPO_URL} ${DATA_DIR}`,
    );
  }
}

const INLINE_SCHEMAS = [
  `create table if not exists fourbyte_signatures (
  selector text not null,
  signature text not null,
  created_at timestamptz not null default now(),
  primary key (selector, signature)
);`,
  `create table if not exists fourbyte_event_signatures (
  topic text not null,
  signature text not null,
  created_at timestamptz not null default now(),
  primary key (topic, signature)
);`,
];

async function loadSchemas() {
  const out = [];
  const files = ["0005_fourbyte.sql", "0006_fourbyte_events.sql"];
  for (let i = 0; i < files.length; i++) {
    const sqlPath = path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      "..",
      "migrations",
      files[i],
    );
    if (fs.existsSync(sqlPath)) out.push(fs.readFileSync(sqlPath, "utf8"));
    else {
      log(`migrations/${files[i]} not found, using inline schema`);
      out.push(INLINE_SCHEMAS[i]);
    }
  }
  return out;
}

/** Parse one selector/topic file into [key, signature] rows. */
async function parseFile(dirPath, file, keyLen) {
  if (!new RegExp(`^[0-9a-f]{${keyLen}}$`).test(file)) return { rows: [], skipped: 1 };
  const raw = await fsp.readFile(path.join(dirPath, file), "utf8");
  const key = `0x${file}`;
  const seen = new Set();
  const rows = [];
  for (const line of raw.split("\n")) {
    const sig = line.trim();
    if (!sig || seen.has(sig)) continue;
    seen.add(sig);
    rows.push([key, sig]);
  }
  return { rows, skipped: 0 };
}

async function flush(pool, table, keyColumn, batch) {
  if (batch.length === 0) return;
  const values = [];
  const params = [];
  batch.forEach(([key, signature], i) => {
    values.push(`($${i * 2 + 1},$${i * 2 + 2})`);
    params.push(key, signature);
  });
  await pool.query(
    `insert into ${table} (${keyColumn}, signature) values ${values.join(",")} on conflict do nothing`,
    params,
  );
}

async function importDataset(pool, ds) {
  const dirPath = path.join(DATA_DIR, ds.dir);
  if (!fs.existsSync(dirPath)) {
    log(`skipping ${ds.label}: no ${ds.dir}/ in checkout`);
    return { files: 0, rows: 0, skipped: 0 };
  }
  const files = (await fsp.readdir(dirPath)).sort();
  const wanted = LIMIT ? files.slice(0, LIMIT) : files;
  const keyColumn = ds.table === "fourbyte_event_signatures" ? "topic" : "selector";
  log(`parsing ${wanted.length} ${ds.label} files from ${ds.dir}/` + (LIMIT ? ` (limit ${LIMIT})` : ""));

  const started = Date.now();
  let batch = [];
  let rows = 0;
  let filesDone = 0;
  let skipped = 0;
  const sample = [];
  for (const file of wanted) {
    const { rows: fileRows, skipped: s } = await parseFile(dirPath, file, ds.keyLen);
    skipped += s;
    for (const row of fileRows) {
      if (sample.length < 3) sample.push(row);
      batch.push(row);
      rows++;
      if (batch.length >= BATCH_ROWS) {
        if (pool) await flush(pool, ds.table, keyColumn, batch);
        batch = [];
      }
      if (rows % LOG_EVERY_ROWS === 0) {
        log(`[${ds.label}] ${rows.toLocaleString()} rows parsed (${filesDone + 1} files, ${((Date.now() - started) / 1000).toFixed(0)}s)`);
      }
    }
    filesDone++;
  }
  if (pool) await flush(pool, ds.table, keyColumn, batch);

  log(`[${ds.label}] done: ${filesDone.toLocaleString()} files, ${rows.toLocaleString()} rows parsed, ${skipped} skipped (non-selector names)`);
  if (DRY_RUN) {
    for (const [k, sig] of sample) log(`  [${ds.label}] ${k}  ${sig}`);
  }
  return { files: filesDone, rows, skipped };
}

async function main() {
  loadWorkerEnv();
  ensureCheckout();
  const datasets = ONLY ? DATASETS.filter((d) => d.label === ONLY) : DATASETS;
  if (datasets.length === 0) throw new Error(`--only must be "selectors" or "topics", got ${ONLY}`);

  let pool = null;
  const before = {};
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
    for (const schema of await loadSchemas()) await pool.query(schema);
    for (const ds of datasets) {
      before[ds.table] = Number(
        (await pool.query(`select count(*)::int as n from ${ds.table}`)).rows[0].n,
      );
    }
    log(`tables ready, rows before: ${JSON.stringify(before)}`);
  }

  let totalRows = 0;
  for (const ds of datasets) {
    const { rows } = await importDataset(pool, ds);
    totalRows += rows;
  }
  log(`total: ${totalRows.toLocaleString()} rows parsed across ${datasets.length} dataset(s)`);

  if (DRY_RUN) {
    log("dry-run: no database writes.");
    return;
  }
  for (const ds of datasets) {
    const after = Number((await pool.query(`select count(*)::int as n from ${ds.table}`)).rows[0].n);
    log(`rows in ${ds.table}: ${before[ds.table]} -> ${after} (+${after - before[ds.table]})`);
  }
  log("cross-check: 4byte.directory API counts were ~1.18M function + ~278k event signatures on 2026-10-17");
  await pool.end();
}

main().catch((err) => {
  console.error(`[import-4byte] FAILED: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
