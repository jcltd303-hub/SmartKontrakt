/**
 * Archive read queries with the Sql handle passed in (the bulk-persist /
 * fourbyte style), so tests can drive them with a fake Sql and no database.
 *
 * Error contract (2026-10-22, improvement #2): a failed query is DATA, not a
 * silent empty result. These functions never throw for a DB failure — they
 * return the error message alongside the empty payload, and the Records tab
 * renders it as a banner with the effective DB identity. Before this, the
 * callers in persist.server.ts caught every error and returned [] / zeros,
 * which hid a wrong-project misconfiguration for hours: Records showed
 * "Connected", all totals 0, and no error anywhere.
 */
import type { Sql } from "../sql-client.ts";
import type { ScanSummary } from "./persist.server.ts";

/** The subset of contract_scans columns the summaries list selects. */
export type ScanSummaryRow = {
  id: string;
  label: string;
  input_kind: string;
  contract_name: string | null;
  target_address?: string | null;
  chain_id?: string | null;
  proxy_info_json?: string | null;
  probes_json?: string | null;
  cert_hash?: string | null;
  source_origin?: string | null;
  analyzer_version?: string | null;
  is_rag_indexed?: boolean | null;
  risk_score: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  balance_wei?: string | null;
  value_usd?: number | null;
  unparsed?: boolean;
  created_at: string;
};

export function summaryFromRow(row: ScanSummaryRow): ScanSummary {
  let hasProxy = false;
  if (row.proxy_info_json) {
    try {
      const p = JSON.parse(row.proxy_info_json);
      hasProxy = Boolean(p?.isProxy);
    } catch {
      hasProxy = false;
    }
  }

  let probesCount = 0;
  if (row.probes_json) {
    try {
      const pr = JSON.parse(row.probes_json);
      probesCount = Array.isArray(pr) ? pr.length : 0;
    } catch {
      probesCount = 0;
    }
  }

  return {
    id: row.id,
    label: row.label,
    inputKind: row.input_kind,
    contractName: row.contract_name,
    targetAddress: row.target_address ?? null,
    chainId: row.chain_id ?? "ethereum",
    riskScore: row.risk_score,
    criticalCount: row.critical_count,
    highCount: row.high_count,
    mediumCount: row.medium_count,
    lowCount: row.low_count,
    infoCount: row.info_count,
    balanceWei: row.balance_wei ?? null,
    valueUsd: row.value_usd === null || row.value_usd === undefined ? null : Number(row.value_usd),
    certHash: row.cert_hash ?? null,
    isRagIndexed: Boolean(row.is_rag_indexed),
    sourceOrigin: row.source_origin ?? "workbench",
    hasProxy,
    probesCount,
    createdAt: row.created_at,
    unparsed: row.unparsed ?? false,
    analyzerVersion: row.analyzer_version ?? null,
  };
}

export type ScanSummariesResult = { summaries: ScanSummary[]; error: string | null };

export type ScansStats = { total: number; critical: number; high: number; ragIndexed: number };

export type ScansStatsResult = { stats: ScansStats; error: string | null };

export type DbSizeTable = { name: string; bytes: number };

/** totalBytes is null when the size could not be read at all (fail soft —
 *  the guardrail is informational and must never break Records). */
export type DatabaseSizeResult = { totalBytes: number | null; tables: DbSizeTable[]; error: string | null };

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Paginated summaries, newest first. Paginated because the Records tab used
 * to hard-cap at 60 with no way to see the rest, so a 43k-address run looked
 * like 60 rows. Values are clamped to integers; the sql tag parameterizes
 * them.
 */
export async function queryScanSummaries(
  sql: Sql,
  opts?: { limit?: number; offset?: number },
): Promise<ScanSummariesResult> {
  const limit = Math.min(Math.max(Math.floor(opts?.limit ?? 60), 1), 500);
  const offset = Math.max(Math.floor(opts?.offset ?? 0), 0);
  try {
    const rows = await sql<ScanSummaryRow>`
      select id, label, input_kind, contract_name, target_address, chain_id,
             proxy_info_json, probes_json, cert_hash, source_origin, is_rag_indexed,
             risk_score, critical_count, high_count, medium_count, low_count, info_count,
             balance_wei, value_usd, unparsed, analyzer_version,
             created_at::text as created_at
      from contract_scans
      order by created_at desc
      limit ${limit} offset ${offset}
    `;
    return { summaries: rows.map(summaryFromRow), error: null };
  } catch (err) {
    console.warn("[kiln] DB scans query failed:", err);
    return { summaries: [], error: errorMessage(err) };
  }
}

/** True totals for the Records stat cards (not per-page sums). */
export async function queryScansStats(sql: Sql): Promise<ScansStatsResult> {
  const zero: ScansStats = { total: 0, critical: 0, high: 0, ragIndexed: 0 };
  try {
    const rows = await sql<{ total: string; critical: string; high: string; rag_indexed: string }>`
      select count(*) as total,
             coalesce(sum(critical_count), 0) as critical,
             coalesce(sum(high_count), 0) as high,
             coalesce(sum(case when is_rag_indexed then 1 else 0 end), 0) as rag_indexed
      from contract_scans`;
    const r = rows[0];
    if (!r) return { stats: zero, error: null };
    const num = (v: string | undefined) => {
      const n = Number.parseInt(v ?? "0", 10);
      return Number.isFinite(n) ? n : 0;
    };
    return {
      stats: { total: num(r.total), critical: num(r.critical), high: num(r.high), ragIndexed: num(r.rag_indexed) },
      error: null,
    };
  } catch (err) {
    console.warn("[kiln] DB scans stats failed:", err);
    return { stats: zero, error: errorMessage(err) };
  }
}

/**
 * Database size guardrail (improvement #3): total database size plus the
 * largest tables, so free-tier quota creep (500 MB cap; the archive hit
 * 580 MB in Oct 2026 before anyone noticed) is visible in the app instead
 * of being discovered via locked writes. Fail soft by contract: any read
 * failure returns totalBytes null + the error, never a throw.
 */
export async function queryDatabaseSize(sql: Sql): Promise<DatabaseSizeResult> {
  let totalBytes: number | null = null;
  let error: string | null = null;
  try {
    const rows = await sql<{ total_bytes: string }>`
      select pg_database_size(current_database())::text as total_bytes`;
    const n = rows[0] ? Number(rows[0].total_bytes) : NaN;
    totalBytes = Number.isFinite(n) ? n : null;
    if (totalBytes === null) error = "pg_database_size returned no row";
  } catch (err) {
    console.warn("[kiln] DB size read failed:", err);
    return { totalBytes: null, tables: [], error: errorMessage(err) };
  }
  let tables: DbSizeTable[] = [];
  try {
    const rows = await sql<{ name: string; bytes: string }>`
      select c.relname as name, pg_total_relation_size(c.oid)::text as bytes
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      where c.relkind in ('r', 'm')
        and n.nspname not in ('pg_catalog', 'information_schema')
      order by pg_total_relation_size(c.oid) desc
      limit 8`;
    tables = rows
      .map((r) => ({ name: r.name, bytes: Number(r.bytes) }))
      .filter((t) => Number.isFinite(t.bytes));
  } catch (err) {
    // The total is the guardrail headline; a failed per-table breakdown
    // degrades to "no breakdown", with the error kept for the tooltip.
    console.warn("[kiln] DB table sizes read failed:", err);
    error = errorMessage(err);
  }
  return { totalBytes, tables, error };
}
