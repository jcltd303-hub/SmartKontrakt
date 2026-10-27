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

/**
 * Severity counts derived from a scan's findings rows — the read-time
 * source of truth for every count the Records surfaces show (2026-10-25
 * counts fix). The stored *_count columns on contract_scans are written
 * at save time and go stale the moment the findings table is edited
 * directly: the rectification SQL rewrote findings.severity across the
 * archive and neither the list badges nor the header totals moved,
 * because both read the stored columns. Reads now derive counts from
 * findings wherever findings rows exist; the stored columns survive only
 * as the fallback for a scan with NO findings rows at all — saves from
 * before the findings table existed, whose stored counts are the only
 * record of what they found. (Every current save path writes the scan
 * row and its findings rows in one transaction — bulk-persist.server.ts
 * is the only insert into either table — so a scan with findings rows
 * always has the complete, current set.)
 */
export type DerivedSeverityCounts = {
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
};

const SEVERITY_COUNT_FIELD = {
  critical: "criticalCount",
  high: "highCount",
  medium: "mediumCount",
  low: "lowCount",
  info: "infoCount",
} as const satisfies Record<string, keyof DerivedSeverityCounts>;

/** Count a severity list (e.g. a loaded scan's findings) into the five
 *  summary count fields. Unknown severities are ignored — they have no
 *  summary field to land in. */
export function countsFromSeverityList(severities: readonly string[]): DerivedSeverityCounts {
  const counts: DerivedSeverityCounts = {
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    infoCount: 0,
  };
  for (const severity of severities) {
    const field = SEVERITY_COUNT_FIELD[severity as keyof typeof SEVERITY_COUNT_FIELD];
    if (field) counts[field]++;
  }
  return counts;
}

type SeverityCountRow = { scan_id: string; severity: string; n: string | number };

/**
 * Per-scan severity counts from the findings table for the given scans
 * (GROUP BY scan_id, severity). The returned map has an entry ONLY for
 * scans with at least one findings row — absence is the legacy signal,
 * and the caller keeps that scan's stored count columns. A present entry
 * is complete: a severity with no rows for that scan counts 0, overriding
 * whatever the stored column says.
 */
export async function queryDerivedSeverityCounts(
  sql: Sql,
  scanIds: readonly string[],
): Promise<Map<string, DerivedSeverityCounts>> {
  const byScan = new Map<string, DerivedSeverityCounts>();
  if (scanIds.length === 0) return byScan;
  const rows = await sql<SeverityCountRow>`
    select scan_id, severity, count(*) as n
    from findings
    where scan_id = any(${[...scanIds]})
    group by scan_id, severity
  `;
  for (const r of rows) {
    if (!r || typeof r.scan_id !== "string") continue;
    let entry = byScan.get(r.scan_id);
    if (!entry) {
      entry = { criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, infoCount: 0 };
      byScan.set(r.scan_id, entry);
    }
    const field = SEVERITY_COUNT_FIELD[r.severity as keyof typeof SEVERITY_COUNT_FIELD];
    if (!field) continue;
    const n = Number(r.n);
    entry[field] += Number.isFinite(n) ? n : 0;
  }
  return byScan;
}

export function summaryFromRow(row: ScanSummaryRow, derived?: DerivedSeverityCounts): ScanSummary {
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
    // Derived counts (from the scan's findings rows) replace the stored
    // columns wholesale when present — see DerivedSeverityCounts. Absent
    // derived counts mean the scan has no findings rows (legacy save) and
    // its stored columns are the only record, so they stand.
    criticalCount: derived ? derived.criticalCount : row.critical_count,
    highCount: derived ? derived.highCount : row.high_count,
    mediumCount: derived ? derived.mediumCount : row.medium_count,
    lowCount: derived ? derived.lowCount : row.low_count,
    infoCount: derived ? derived.infoCount : row.info_count,
    balanceWei: row.balance_wei ?? null,
    valueUsd: row.value_usd === null || row.value_usd === undefined ? null : Number(row.value_usd),
    certHash: row.cert_hash ?? null,
    sourceOrigin: row.source_origin ?? "workbench",
    hasProxy,
    probesCount,
    createdAt: row.created_at,
    unparsed: row.unparsed ?? false,
    analyzerVersion: row.analyzer_version ?? null,
  };
}

/** Effective store for an archive payload: "remote" is the only state in
 *  which the numbers describe the configured database. Set by the query
 *  functions to "remote"; the persist wrappers override it from
 *  getDbConnectionState() when the configured connection FAILED or nothing
 *  is configured — in both cases the payload carries an error, never
 *  fabricated zeros (the embedded fallback is removed; there is no
 *  substitute store whose zeros could be reported). */
export type ArchiveDbState = "remote" | "failed" | "unconfigured";

export type ScanSummariesResult = {
  summaries: ScanSummary[];
  error: string | null;
  warning: string | null;
  dbState: ArchiveDbState;
  /** Classified connection failure (password-free) when dbState is failed. */
  dbError: string | null;
};

export type ScansStats = { total: number; critical: number; high: number; ragIndexed: number };

export type ScansStatsResult = { stats: ScansStats; error: string | null; warning: string | null; dbState: ArchiveDbState; dbError: string | null };

export type DbSizeTable = { name: string; bytes: number };

/** totalBytes is null when the size could not be read at all (fail soft —
 *  the guardrail is informational and must never break Records). */
export type DatabaseSizeResult = { totalBytes: number | null; tables: DbSizeTable[]; error: string | null; dbState: ArchiveDbState; dbError: string | null };

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Column sets for the summaries select, oldest-schema first principles: a
 * worker-grown archive can predate the migrations that added the newer
 * columns (unparsed 0007, balance 0011, value_at_risk 0012,
 * analyzer_version 0014). One missing column must not zero the whole list —
 * queryScanSummaries degrades to the columns that exist and says so via the
 * result warning instead.
 */
const ESSENTIAL_SUMMARY_COLUMNS = [
  "id",
  "label",
  "input_kind",
  "contract_name",
  "risk_score",
  "critical_count",
  "high_count",
  "medium_count",
  "low_count",
  "info_count",
  "created_at",
] as const;

const OPTIONAL_SUMMARY_COLUMNS = [
  "target_address",
  "chain_id",
  "proxy_info_json",
  "probes_json",
  "cert_hash",
  "source_origin",
  "balance_wei",
  "value_usd",
  "unparsed",
  "analyzer_version",
] as const;

/** Canonical render order for the summaries select (matches summaryFromRow). */
const SUMMARY_COLUMN_ORDER = [
  "id",
  "label",
  "input_kind",
  "contract_name",
  "target_address",
  "chain_id",
  "proxy_info_json",
  "probes_json",
  "cert_hash",
  "source_origin",
  "risk_score",
  "critical_count",
  "high_count",
  "medium_count",
  "low_count",
  "info_count",
  "balance_wei",
  "value_usd",
  "unparsed",
  "analyzer_version",
  "created_at",
] as const;

function isMissingColumnError(err: unknown): boolean {
  const msg = errorMessage(err);
  return /does not exist/i.test(msg) && /column/i.test(msg) || /undefined column/i.test(msg);
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
             proxy_info_json, probes_json, cert_hash, source_origin,
             risk_score, critical_count, high_count, medium_count, low_count, info_count,
             balance_wei, value_usd, unparsed, analyzer_version,
             created_at::text as created_at
      from contract_scans
      order by created_at desc
      limit ${limit} offset ${offset}
    `;
    let derived: Map<string, DerivedSeverityCounts>;
    try {
      derived = await queryDerivedSeverityCounts(sql, rows.map((r) => r.id));
    } catch (countsErr) {
      // The page read fine but its counts cannot be derived. Falling back
      // to the stored columns here would silently resurrect the desync
      // this read path exists to remove, so the failure surfaces with the
      // same error payload as a failed page read.
      console.warn("[kiln] DB findings counts query failed:", countsErr);
      return { summaries: [], error: errorMessage(countsErr), warning: null, dbState: "remote", dbError: null };
    }
    return { summaries: rows.map((r) => summaryFromRow(r, derived.get(r.id))), error: null, warning: null, dbState: "remote", dbError: null };
  } catch (err) {
    if (!isMissingColumnError(err)) {
      console.warn("[kiln] DB scans query failed:", err);
      return { summaries: [], error: errorMessage(err), warning: null, dbState: "remote", dbError: null };
    }
    // Schema drift: the archive predates one or more selected columns.
    // Introspect what contract_scans actually has and retry with the
    // intersection — partial rows beat a fake-empty archive. The missing
    // columns are named in the warning so the state is visible, and
    // summaryFromRow already null-tolerates every absent field.
    try {
      const cols = await sql<{ column_name: string }>`
        select column_name from information_schema.columns
        where table_schema = 'public' and table_name = 'contract_scans'
      `;
      const present = new Set(cols.map((c) => c.column_name));
      const missingEssential = ESSENTIAL_SUMMARY_COLUMNS.filter((c) => !present.has(c));
      if (missingEssential.length > 0) {
        console.warn("[kiln] DB scans query failed:", err);
        return { summaries: [], error: errorMessage(err), warning: null, dbState: "remote", dbError: null };
      }
      const missing = OPTIONAL_SUMMARY_COLUMNS.filter((c) => !present.has(c));
      const selected = SUMMARY_COLUMN_ORDER.filter((c) => present.has(c));
      const selectList = selected
        .map((c) => (c === "created_at" ? "created_at::text as created_at" : c))
        .join(", ");
      const rows = await sql.query<ScanSummaryRow>(
        `select ${selectList} from contract_scans order by created_at desc limit $1 offset $2`,
        [limit, offset],
      );
      // Same findings-derived counts as the primary path, but best-effort:
      // the drift contract is partial rows over a fake-empty archive, so
      // if the counts cannot be read either, the stored columns stand and
      // the warning below already says the archive is behind this build.
      let derived = new Map<string, DerivedSeverityCounts>();
      try {
        derived = await queryDerivedSeverityCounts(sql, rows.map((r) => r.id));
      } catch {
        // Stored columns stand; see the comment above.
      }
      return {
        summaries: rows.map((r) => summaryFromRow(r, derived.get(r.id))),
        error: null,
        dbState: "remote",
        dbError: null,
        warning:
          `Archive schema is older than this build: contract_scans is missing ${missing.join(", ")} — ` +
          `showing partial rows. Run the app migrations against this database to restore the full record view.`,
      };
    } catch {
      console.warn("[kiln] DB scans query failed:", err);
      return { summaries: [], error: errorMessage(err), warning: null, dbState: "remote", dbError: null };
    }
  }
}

/** True totals for the Records stat cards (not per-page sums). The
 *  critical/high totals are counted from the findings table — the same
 *  read-time source of truth as the per-scan list counts — PLUS the
 *  stored columns of scans that have no findings rows at all (the legacy
 *  fallback, mirroring queryScanSummaries). The headline therefore
 *  equals the sum of the per-scan derived counts by construction, and a
 *  direct findings edit moves it immediately. The headline counts and
 *  the RAG count were separate queries while is_rag_indexed existed; RAG is
 *  gone (migration 0019) and ragIndexed now reports 0 unconditionally. */
export async function queryScansStats(sql: Sql): Promise<ScansStatsResult> {
  const zero: ScansStats = { total: 0, critical: 0, high: 0, ragIndexed: 0 };
  const num = (v: string | undefined) => {
    const n = Number.parseInt(v ?? "0", 10);
    return Number.isFinite(n) ? n : 0;
  };
  let base: ScansStats;
  try {
    const rows = await sql<{ total: string; critical: string; high: string }>`
      select count(*) as total,
             (select count(*) from findings where severity = 'critical')
               + coalesce((select sum(cs.critical_count) from contract_scans cs
                           where not exists (select 1 from findings f where f.scan_id = cs.id)), 0) as critical,
             (select count(*) from findings where severity = 'high')
               + coalesce((select sum(cs.high_count) from contract_scans cs
                           where not exists (select 1 from findings f where f.scan_id = cs.id)), 0) as high
      from contract_scans`;
    const r = rows[0];
    base = r
      ? { total: num(r.total), critical: num(r.critical), high: num(r.high), ragIndexed: 0 }
      : { ...zero };
  } catch (err) {
    console.warn("[kiln] DB scans stats failed:", err);
    return { stats: zero, error: errorMessage(err), warning: null, dbState: "remote", dbError: null };
  }
  // RAG was removed (migration 0019): rag_knowledge_chunks is dropped and
  // is_rag_indexed with it, so there is no count to make and nothing to warn
  // about. The field stays at 0 for the shapes that still read it.
  base.ragIndexed = 0;
  return { stats: base, error: null, warning: null, dbState: "remote", dbError: null };
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
    return { totalBytes: null, tables: [], error: errorMessage(err), dbState: "remote", dbError: null };
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
  return { totalBytes, tables, error, dbState: "remote", dbError: null };
}
