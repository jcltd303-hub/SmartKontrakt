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
    const key = `${r.chain_id}:${r.addr}`;
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
