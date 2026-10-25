/**
 * Which saved records are current, and which an older analyzer produced.
 *
 * Its own module, deliberately: it imports only `Sql` and the analyzer stamp —
 * no `@/` alias, no engine, no DB singleton — so the test runner can load it
 * under Node's strip-types ESM. (persist.server.ts cannot be loaded that way: it
 * uses the bundler's `@/` alias and extensionless imports, which Vite resolves
 * and Node does not.)
 *
 * The `sql` client is a required parameter for the same reason — the caller
 * supplies it, so there is no hidden dependency on the app's global connection.
 */
import type { Sql } from "../sql-client.ts";
import { analyzerStamp } from "./analyzer-version.ts";

/**
 * Of the requested (chain, address) pairs, which are already saved by the
 * CURRENT analyzer — safe to skip — and which are saved only by an older one,
 * which is stale and must be re-analyzed?
 *
 * One query, bounded by the run size (it uses the same
 * (chain_id, lower(target_address)) index as the plain skip check). A key with
 * ANY current row is current: the archive can hold several scans of one
 * address, and a single up-to-date record means there is nothing to refresh.
 */
export async function savedScanVersions(
  sql: Sql,
  wanted: { chainId: string; address: string }[],
  current: string = analyzerStamp(),
): Promise<{ current: Set<string>; stale: Set<string> }> {
  const currentSet = new Set<string>();
  const staleSet = new Set<string>();
  const addrs = [...new Set(wanted.map((w) => w.address.toLowerCase()))];
  if (addrs.length === 0) return { current: currentSet, stale: staleSet };
  const rows = await sql<{ chain_id: string; addr: string; analyzer_version: string | null }>`
    select chain_id, lower(target_address) as addr, analyzer_version
    from contract_scans
    where lower(target_address) = any(${addrs}::text[])
  `;
  for (const r of rows) {
    // Keys are (chain, lower-address) in the canonical chain spelling.
    // The chain is lowercased on BOTH sides of every comparison (here
    // for stored rows, in shouldSkipInRun and the worker for wanted
    // items): a row saved under a case variant ("Ethereum") is the same
    // chain as "ethereum", and keying on the raw stored spelling would
    // make that row invisible to the skip check forever. A missing
    // chain reads as "ethereum", the same default scan-archive uses.
    const key = `${(r.chain_id || "ethereum").toLowerCase()}:${r.addr}`;
    if (r.analyzer_version === current) currentSet.add(key);
    else if (!currentSet.has(key)) staleSet.add(key);
  }
  // A key with a current row is never stale, whatever else the archive holds.
  for (const key of currentSet) staleSet.delete(key);
  return { current: currentSet, stale: staleSet };
}

/** How much of the archive the current analyzer would refresh. */
export async function scanFreshness(
  sql: Sql,
  current: string = analyzerStamp(),
): Promise<{ total: number; current: number; stale: number }> {
  const rows = await sql<{ total: string; current: string }>`
    select count(*) as total,
           coalesce(sum(case when analyzer_version = ${current} then 1 else 0 end), 0) as current
    from contract_scans`;
  const r = rows[0];
  const total = Number.parseInt(r?.total ?? "0", 10) || 0;
  const cur = Number.parseInt(r?.current ?? "0", 10) || 0;
  return { total, current: cur, stale: Math.max(total - cur, 0) };
}

/**
 * Per-item re-check for a run already in flight (the pipeline worker's
 * in-run dedupe): has THIS (chain, address) become skippable since the
 * run started? The /start check cannot see rows saved after it ran — a
 * twin earlier in the same file whose batch has since flushed, or another
 * writer (the browser pipeline) saving the same address mid-run.
 *
 * The policy mapping mirrors /start exactly:
 *   refresh=all   — never skip (the run asked to re-analyze everything)
 *   refresh=none  — any saved row counts as done
 *   refresh=stale — skip only a row saved by the CURRENT analyzer;
 *                   a stale (or pre-stamp NULL) row is re-analyzed
 *
 * Never throws: any failure (DB down, schema drift) returns false so the
 * caller proceeds with the analysis — a dedupe check must never stall
 * or kill a run.
 */
export async function shouldSkipInRun(
  sql: Sql,
  wanted: { chainId: string; address: string },
  refresh: string,
  current: string = analyzerStamp(),
): Promise<boolean> {
  if (refresh === "all") return false;
  try {
    const { current: currentSet, stale: staleSet } = await savedScanVersions(sql, [wanted], current);
    const key = `${wanted.chainId.toLowerCase()}:${wanted.address.toLowerCase()}`;
    if (refresh === "none") return currentSet.has(key) || staleSet.has(key);
    return currentSet.has(key);
  } catch {
    return false;
  }
}

/**
 * Preflight: the columns a pipeline run actually depends on must exist
 * before it starts —
 *   contract_scans.analyzer_version (0014): the freshness skip reads it
 *     and every save writes it;
 *   findings.corroborated (0016): every bulk save writes it;
 *   contract_scans.resnet_json (0018): every bulk save writes it.
 * Checking only the 0014 column (the original gate) let a database that
 * predates 0016/0018 start a run whose every flush then failed deep
 * inside the batch writer with a raw "column does not exist" — the run
 * parked with no hint that migrations were the fix. Fail here instead,
 * naming each missing column and its migration. Reconnecting the
 * database in the app applies EVERY pending embedded migration, so the
 * one instruction covers all three.
 */
const REQUIRED_SCHEMA_COLUMNS: { table: string; column: string; migration: string }[] = [
  { table: "contract_scans", column: "analyzer_version", migration: "0014" },
  { table: "findings", column: "corroborated", migration: "0016" },
  { table: "contract_scans", column: "resnet_json", migration: "0018" },
];

export async function assertFreshnessSchema(sql: Sql): Promise<void> {
  const rows = await sql<{ table_name: string; column_name: string }>`
    select table_name, column_name from information_schema.columns
    where (table_name = 'contract_scans' and column_name in ('analyzer_version', 'resnet_json'))
       or (table_name = 'findings' and column_name = 'corroborated')`;
  const present = new Set(rows.map((r) => `${r.table_name}.${r.column_name}`));
  const missing = REQUIRED_SCHEMA_COLUMNS.filter((c) => !present.has(`${c.table}.${c.column}`));
  if (missing.length > 0) {
    const list = missing
      .map((c) => `${c.table}.${c.column} (migration ${c.migration} not applied)`)
      .join(", ");
    throw new Error(
      `Required schema column(s) missing: ${list}. ` +
      "Apply migrations by reconnecting the Supabase database in the app " +
      "(Connect to Supabase), then start the run again.",
    );
  }
}
