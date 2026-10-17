#!/usr/bin/env node
/**
 * Build a rerun list of addresses whose saved scans are marked critical
 * (critical_count >= 1) and, with --delete, clear their old rows so the
 * pipeline worker's skip-check (already-saved (chain, address) pairs)
 * does not skip them on the rerun.
 *
 * Why the delete is needed: the worker skips any (chain, address) pair
 * already in contract_scans. A rerun of already-saved addresses would
 * come back "0 completed, N skipped" without --delete.
 *
 * Usage (from the repo root, on the phone):
 *   node scripts/rerun-critical.mjs [--chain ethereum] [--min-critical 1]
 *     [--out ./critical.csv] [--limit N] [--delete]
 *
 * Default (no --delete): dry-run — writes the CSV, prints the counts,
 * deletes nothing. With --delete: deletes the matching contract_scans
 * rows (findings + scan_payloads follow via ON DELETE CASCADE) and
 * writes the CSV.
 *
 * Also prints the 4byte table counts — if both are 0 the import has
 * not run yet and 4byte enrichment on the rerun will be a silent no-op.
 * Run `node scripts/import-4byte.mjs` first in that case.
 *
 * DATABASE_URL comes from the environment, or from pipeline-worker/.env
 * when it is not set (same as scripts/import-4byte.mjs).
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
function flagValue(name, fallback) {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : fallback;
}
const CHAIN = flagValue("--chain", "ethereum");
const MIN_CRITICAL = Number(flagValue("--min-critical", "1"));
const OUT = path.resolve(flagValue("--out", "./critical.csv"));
const LIMIT = flagValue("--limit", null) ? Number(flagValue("--limit", null)) : null;
const DO_DELETE = args.includes("--delete");

const log = (msg) => console.log(`[rerun-critical] ${msg}`);

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
  for (const raw of fs.readFileSync(envPath, "utf8").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    if (key && !(key in process.env)) process.env[key] = line.slice(eq + 1).trim();
  }
}

async function main() {
  loadWorkerEnv();
  if (!process.env.DATABASE_URL) {
    console.error("[rerun-critical] DATABASE_URL not set and pipeline-worker/.env has none.");
    process.exit(1);
  }
  const { Pool } = await import("pg");
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL.replace(/([?&])sslmode=[^&]*/g, "$1").replace(/[?&]$/, ""),
    ssl: { rejectUnauthorized: false },
  });
  try {
    // 4byte tables: warn loudly if the import has not run.
    let selCount = 0;
    let topCount = 0;
    try {
      ({ rows: [{ count: selCount }] } = await pool.query(
        "select count(*)::int as count from fourbyte_signatures",
      ));
      ({ rows: [{ count: topCount }] } = await pool.query(
        "select count(*)::int as count from fourbyte_event_signatures",
      ));
    } catch {
      log("4byte tables missing/unreadable — the 4byte import has not run. Enrichment will be a no-op.");
    }
    log(`4byte tables: ${selCount} selectors, ${topCount} topics`);
    if (selCount === 0 && topCount === 0) {
      log("WARNING: both 4byte tables are empty — run `node scripts/import-4byte.mjs` BEFORE the rerun, or the rerun gets no 4byte/event data.");
    }

    const limitSql = LIMIT ? ` limit ${LIMIT}` : "";
    const { rows } = await pool.query(
      `select distinct lower(target_address) as address, max(critical_count) as critical_count
         from contract_scans
        where chain_id = $1 and critical_count >= $2 and target_address is not null
        group by lower(target_address)
        order by critical_count desc, address${limitSql}`,
      [CHAIN, MIN_CRITICAL],
    );
    log(`chain=${CHAIN} min_critical=${MIN_CRITICAL}: ${rows.length} critical address(es)`);
    if (rows.length === 0) {
      log("Nothing to rerun.");
      return;
    }
    for (const r of rows.slice(0, 10)) log(`  ${r.address} (critical_count ${r.critical_count})`);
    if (rows.length > 10) log(`  ... and ${rows.length - 10} more`);

    if (DO_DELETE) {
      const del = await pool.query(
        `delete from contract_scans
          where chain_id = $1 and critical_count >= $2 and target_address is not null
            and lower(target_address) = any($3::text[])`,
        [CHAIN, MIN_CRITICAL, rows.map((r) => r.address)],
      );
      log(`Deleted ${del.rowCount} old scan row(s) (findings + payloads cascaded) — the worker will no longer skip these.`);
    } else {
      log("Dry run: no rows deleted. Re-run with --delete to clear the old rows so the worker does not skip them.");
    }

    fs.writeFileSync(OUT, rows.map((r) => r.address).join("\n") + "\n");
    log(`Wrote ${rows.length} address(es) to ${OUT}`);
    log("Rerun with:");
    log(`  curl -s -X POST http://127.0.0.1:8788/start -H 'Content-Type: application/json' -d '{"addressesFile":"${OUT}","chainId":"${CHAIN}","aiSecondPass":true,"delayMs":200,"deepAgent":true,"deepAgentMaxItems":250,"deepAgentMinSeverity":"high"}'`);
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error(`[rerun-critical] ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
