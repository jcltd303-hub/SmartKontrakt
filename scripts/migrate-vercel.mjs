#!/usr/bin/env node
/**
 * Vercel-aware deploy-time database migrator (node-postgres, `pg`).
 *
 * Runs during `npm run build` — on every Vercel deploy — applying pending files
 * in ../migrations. Each file is applied in one transaction and recorded in a
 * `_migrations` table, so it runs once and is safe to re-run.
 *
 * Connection resolution (first valid Postgres URI wins):
 *   1. DATABASE_URL — explicit override.
 *   2. POSTGRES_URL_NON_POOLING — direct connection, preferred for DDL/migrations.
 *   3. POSTGRES_PRISMA_URL — Vercel Supabase integration pooler URL.
 *   4. POSTGRES_URL — Vercel Supabase integration pooler URL.
 *
 * The Vercel Supabase integration syncs POSTGRES_* for preview + production,
 * so a Vercel deploy migrates its Vercel-enabled Supabase project with no
 * manual DATABASE_URL copy-paste. No credentials are read from files and none
 * are committed — the values come only from the deploy environment.
 *
 * No Postgres URL in the environment -> skip (local / preview builds without
 * a database). Runtime auto-migration in src/lib/db.ts covers the same files
 * on first connection when a database is present.
 *
 * The read is non-recursive: nested `*.sql` files under a subdirectory are
 * not applied.
 */
import { readdir, readFile } from "node:fs/promises";
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import pg from "pg";
import { pendingMigrations } from "./migration-plan.mjs";
import { encodePostgresCredentials, looksLikePlaceholder } from "../src/lib/pg-url.mjs";

function cleanPostgresUrl(value) {
  const trimmed = value?.trim();
  if (!trimmed) return undefined;
  if (looksLikePlaceholder(trimmed)) return undefined;
  if (trimmed.startsWith("postgresql://") || trimmed.startsWith("postgres://")) {
    const encoded = encodePostgresCredentials(trimmed);
    try {
      new URL(encoded);
      return encoded;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

export function resolveMigrateDatabaseUrl(env = process.env) {
  return (
    cleanPostgresUrl(env.DATABASE_URL) ??
    cleanPostgresUrl(env.POSTGRES_URL_NON_POOLING) ??
    cleanPostgresUrl(env.POSTGRES_PRISMA_URL) ??
    cleanPostgresUrl(env.POSTGRES_URL)
  );
}

/**
 * Load `.env` (repo root) and `pipeline-worker/.env` before resolving the URL.
 *
 * Nothing loaded these for scripts: the app's `with-app-env.mjs` only merges
 * `VITE_`-prefixed keys from `.grok/app-env.json`, and the worker has its own
 * loader for `pipeline-worker/.env`. So `npm run db:migrate` on a machine whose
 * URL lives in a `.env` file printed "No Postgres URL in environment — skipping"
 * and did nothing, which is exactly the wrong answer when you are trying to
 * apply a migration.
 *
 * Existing `process.env` still wins, so an explicit shell override beats a file,
 * and on Vercel there are no such files — this is a no-op there. Root `.env` is
 * read first, so the app's config wins over `pipeline-worker/.env` when both
 * name a URL (they should name the same project).
 */
function loadEnvFiles() {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  for (const envPath of [join(root, ".env"), join(root, "pipeline-worker", ".env")]) {
    let text;
    try {
      text = readFileSync(envPath, "utf8");
    } catch {
      continue; // no such file: nothing to load
    }
    // Last occurrence in the file wins (standard dotenv behaviour); an existing
    // process.env entry still wins over the file.
    const fileVars = new Map();
    for (const raw of text.split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      const eq = line.indexOf("=");
      if (eq === -1) continue;
      const key = line.slice(0, eq).trim();
      if (!key) continue;
      let value = line.slice(eq + 1).trim();
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }
      fileVars.set(key, value);
    }
    for (const [key, value] of fileVars) {
      if (process.env[key] === undefined) process.env[key] = value;
    }
  }
}

loadEnvFiles();

const databaseUrl = resolveMigrateDatabaseUrl();

const migrationsDir = join(dirname(fileURLToPath(import.meta.url)), "..", "migrations");

async function run() {
  if (!databaseUrl) {
    console.log(
      "[migrate] No Postgres URL in environment (DATABASE_URL / POSTGRES_URL_NON_POOLING / POSTGRES_PRISMA_URL / POSTGRES_URL) — skipping. " +
        "Connect the Vercel Supabase integration or set DATABASE_URL to migrate on deploy.",
    );
    return;
  }
  await main();
}

async function main() {
  let entries;
  try {
    entries = await readdir(migrationsDir);
  } catch {
    console.log("[migrate] no migrations/ directory — nothing to do.");
    return;
  }
  if (pendingMigrations(entries, []).length === 0) {
    console.log("[migrate] no migrations — nothing to do.");
    return;
  }

  const pool = new pg.Pool({
    connectionString: databaseUrl,
    max: 1,
    connectionTimeoutMillis: 30000,
    ssl: { rejectUnauthorized: false },
  });
  // Connect with retries: a paused Supabase project can take 20-30s to wake
  // on first connection, and a single 10s attempt timed out in Vercel builds.
  // If the DB is still unreachable after retries, warn and let the build
  // SUCCEED — the runtime auto-migration (embedded SQL in
  // src/lib/migrations-sql.ts) retries on each cold start / first DB
  // connection, so a DB that wakes later still gets its tables. Failing the
  // build here (tried in 97f1bfa) turned a transient cold-start timeout
  // into a hard ERROR deploy and left prod on the old code with no tables.
  let client;
  let lastConnErr;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      client = await pool.connect();
      lastConnErr = undefined;
      break;
    } catch (connErr) {
      lastConnErr = connErr;
      console.warn(`[migrate] connect attempt ${attempt}/3 failed: ${connErr.message}`);
      if (attempt < 3) await new Promise((r) => setTimeout(r, 10000));
    }
  }
  if (!client) {
    console.warn(
      "[migrate] could not connect to PostgreSQL database after 3 attempts — " +
        "skipping deploy-time migration. Runtime auto-migration will retry on " +
        "first DB connection. Last error: " +
        (lastConnErr?.message || "unknown"),
    );
    await pool.end().catch(() => {});
    return;
  }

  try {
    await client.query(
      "CREATE TABLE IF NOT EXISTS _migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
    );
    const applied = (await client.query("SELECT name FROM _migrations")).rows.map(
      (r) => r.name,
    );

    let count = 0;
    for (const { name } of pendingMigrations(entries, applied)) {
      const text = await readFile(join(migrationsDir, name), "utf8");
      try {
        await client.query("BEGIN");
        await client.query(text);
        await client.query("INSERT INTO _migrations (name) VALUES ($1)", [name]);
        await client.query("COMMIT");
      } catch (err) {
        console.error(`[migrate] error applying ${name}`);
        try {
          await client.query("ROLLBACK");
        } catch {
          // ROLLBACK fails when the connection died — keep the original error.
        }
        throw err;
      }
      console.log(`[migrate] applied ${name}`);
      count += 1;
    }
    console.log(count ? `[migrate] done — ${count} migration(s) applied.` : "[migrate] up to date.");
  } finally {
    client.release();
    await pool.end();
  }
}

function isMainModule() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isMainModule()) {
  run().catch((err) => {
    console.error("[migrate] failed:", err?.message || err);
    for (const key of ["code", "detail", "hint", "position", "where"]) {
      if (err?.[key] != null) console.error(`[migrate]   ${key}: ${err[key]}`);
    }
    process.exit(1);
  });
}
