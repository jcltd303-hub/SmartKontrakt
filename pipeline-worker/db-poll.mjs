/**
 * Read-only Supabase poll for worker (pipeline-origin) entries.
 * Run on the phone, where pg reaches Supabase (this VM's egress blocks
 * raw Postgres). Reads DATABASE_URL from pipeline-worker/.env only.
 * Prints totals, per-source counts, and the 10 newest pipeline rows.
 * Never writes.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const DIR = path.dirname(fileURLToPath(import.meta.url));

function envValue(key) {
  for (const raw of fs.readFileSync(path.join(DIR, ".env"), "utf8").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    if (line.slice(0, eq).trim() !== key) continue;
    let v = line.slice(eq + 1).trim();
    if (
      (v.startsWith('"') && v.endsWith('"')) ||
      (v.startsWith("'") && v.endsWith("'"))
    ) {
      v = v.slice(1, -1);
    }
    return v;
  }
  return undefined;
}

const client = new pg.Client({ connectionString: envValue("DATABASE_URL") });
await client.connect();
try {
  const { rows: colRows } = await client.query(
    "SELECT column_name FROM information_schema.columns " +
      "WHERE table_schema='public' AND table_name='contract_scans' ORDER BY ordinal_position",
  );
  const cols = new Set(colRows.map((r) => r.column_name));
  const { rows: totalRows } = await client.query("SELECT count(*) AS n FROM contract_scans");
  console.log("total scans:", totalRows[0].n);
  const { rows: bySource } = await client.query(
    "SELECT source_origin, count(*) AS n FROM contract_scans GROUP BY source_origin ORDER BY n DESC",
  );
  console.log("by source_origin:", JSON.stringify(bySource));
  const ts = ["created_at", "updated_at", "inserted_at", "scanned_at"].find((c) => cols.has(c));
  const pick = [
    "target_address", "chain_id", "risk_score", "critical_count",
    "high_count", "medium_count", "ai_status", "label", "contract_name",
  ].filter((c) => cols.has(c));
  const { rows: recent } = await client.query(
    `SELECT ${pick.join(", ")} FROM contract_scans WHERE source_origin='pipeline'` +
      (ts ? ` ORDER BY ${ts} DESC NULLS LAST` : "") +
      " LIMIT 10",
  );
  for (const r of recent) console.log(JSON.stringify(r));
  if (ts) {
    const { rows: range } = await client.query(
      `SELECT min(${ts}) AS first, max(${ts}) AS last, count(*) AS n ` +
        "FROM contract_scans WHERE source_origin='pipeline'",
    );
    console.log("pipeline ts range:", JSON.stringify(range[0]));
  }
} finally {
  await client.end();
}
