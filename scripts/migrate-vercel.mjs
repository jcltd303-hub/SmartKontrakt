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
 * The read is non-recursive, so the opt-in auth schema under migrations/auth/
 * is not applied to an app that never asked for sign-in.
 */
import { readdir, readFile } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import pg from "pg";
import { pendingMigrations } from "./migration-plan.mjs";

function cleanPostgresUrl(value) {
  const trimmed = value?.trim();
  if (!trimmed) return undefined;
  if (trimmed.startsWith("postgresql://") || trimmed.startsWith("postgres://")) {
    return trimmed;
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
    connectionTimeoutMillis: 10000,
    ssl: { rejectUnauthorized: false },
  });
  let client;
  try {
    client = await pool.connect();
  } catch (connErr) {
    console.warn("[migrate] could not connect to PostgreSQL database:", connErr.message);
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
