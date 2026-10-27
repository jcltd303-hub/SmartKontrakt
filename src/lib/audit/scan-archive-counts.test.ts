import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { createSqlClient } from "../sql-client.ts";
import type { Sql } from "../sql-client.ts";
import {
  countsFromSeverityList,
  queryDerivedSeverityCounts,
  queryScanSummaries,
  queryScansStats,
  summaryFromRow,
  type ScanSummaryRow,
} from "./scan-archive.server.ts";

/**
 * Counts fix (2026-10-25): the Records list badges, the header stat
 * cards and the dossier header all read severity counts derived from the
 * findings table at read time. The stored *_count columns on
 * contract_scans are save-time snapshots — the rectification SQL edited
 * findings.severity directly and the screen never moved, because every
 * surface read the snapshots. These tests run the REAL queries against
 * PGlite (the dispositions-test harness pattern) so the SQL itself is
 * pinned, not just its parsing:
 *
 *   - a scan whose stored counts disagree with its findings rows reports
 *     the findings-derived counts in summaries AND stats (and, via the
 *     summaryFromRow seam below, in loadScan);
 *   - a scan with NO findings rows keeps its stored counts (legacy
 *     pre-findings-table saves must not be zeroed);
 *   - stats totals equal the findings counts — and, on a mixed archive,
 *     the sum of the per-scan derived counts.
 *
 * loadScan itself cannot be driven here: its Sql comes from getSql()
 * (a real pg wire connection; this harness has none — the same limit
 * persist-nofallback.test.ts documents). Its wiring is pinned by the
 * source guard at the bottom plus the seam tests of the exact helpers
 * it calls (countsFromSeverityList + summaryFromRow).
 */

const MIGRATIONS = [
  "0002_scans.sql",
  "0003_comprehensive_records_and_rag.sql",
  "0004_poc_results.sql",
  "0005_fourbyte.sql",
  "0006_fourbyte_events.sql",
  "0007_unparsed.sql",
  "0008_finding_poc_runs.sql",
  "0009_rag_fts.sql",
  "0010_indexes.sql",
  "0011_balance.sql",
  "0012_value_at_risk.sql",
  "0013_poc_run_idempotency.sql",
  "0014_analyzer_version.sql",
  "0015_auditor_dispositions.sql",
  "0016_finding_corroborated.sql",
  "0017_fp_signatures.sql",
  "0018_resnet_result.sql",
];

async function database(): Promise<{ pg: PGlite; sql: Sql }> {
  const pg = new PGlite();
  await pg.waitReady;
  for (const f of MIGRATIONS) {
    await pg.exec(await readFile(new URL(`../../../migrations/${f}`, import.meta.url), "utf8"));
  }
  const sql = createSqlClient(
    async <T>(text: string, params: unknown[]) => (await pg.query<T>(text, params)).rows,
    (work) => pg.transaction((tx) => work(async <T>(text: string, params: unknown[]) => (await tx.query<T>(text, params)).rows)),
  );
  return { pg, sql };
}

type StoredCounts = { critical: number; high: number; medium: number; low: number; info: number };

async function insertScan(pg: PGlite, id: string, stored: StoredCounts, createdAt: string): Promise<void> {
  await pg.query(
    `insert into contract_scans (id, label, input_kind, contract_name, risk_score,
       critical_count, high_count, medium_count, low_count, info_count, summary, inventory_json, created_at)
     values ($1, $2, 'source', $2, 50, $3, $4, $5, $6, $7, 'summary', '{}', $8)`,
    [id, id, stored.critical, stored.high, stored.medium, stored.low, stored.info, createdAt],
  );
}

async function insertFinding(pg: PGlite, scanId: string, ord: number, severity: string): Promise<void> {
  await pg.query(
    `insert into findings (id, scan_id, ord, severity, title, confidence, detector, summary, walkthrough)
     values ($1, $2, $3, $4, 't', 'high', 'counts-test', 's', 'w')`,
    [`${scanId}:${ord}`, scanId, ord, severity],
  );
}

const countsOf = (s: {
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
}): StoredCounts => ({
  critical: s.criticalCount,
  high: s.highCount,
  medium: s.mediumCount,
  low: s.lowCount,
  info: s.infoCount,
});

test("summaries + stats: findings-derived counts replace stale stored columns wholesale", async () => {
  const { pg, sql } = await database();
  try {
    // Stored columns claim 5 of everything (a rectified archive looks
    // exactly like this: findings edited, snapshots frozen). The
    // findings rows are the truth: 2 critical, 1 high, 2 info.
    await insertScan(pg, "scan-fixed", { critical: 5, high: 5, medium: 5, low: 5, info: 5 }, "2026-10-25T10:00:00Z");
    await insertFinding(pg, "scan-fixed", 0, "critical");
    await insertFinding(pg, "scan-fixed", 1, "critical");
    await insertFinding(pg, "scan-fixed", 2, "high");
    await insertFinding(pg, "scan-fixed", 3, "info");
    await insertFinding(pg, "scan-fixed", 4, "info");

    const { summaries, error } = await queryScanSummaries(sql);
    assert.equal(error, null);
    assert.equal(summaries.length, 1);
    // Medium/low derive to ZERO despite stored 5s — a present derived
    // set is complete, not a per-severity merge with the snapshots.
    assert.deepEqual(countsOf(summaries[0]!), { critical: 2, high: 1, medium: 0, low: 0, info: 2 });

    const { stats, error: statsError } = await queryScansStats(sql);
    assert.equal(statsError, null);
    assert.deepEqual(stats, { total: 1, critical: 2, high: 1, ragIndexed: 0 });
  } finally {
    await pg.close();
  }
});

test("legacy fallback: a scan with no findings rows keeps its stored counts everywhere", async () => {
  const { pg, sql } = await database();
  try {
    // Pre-findings-table save: stored counts are the only record of what
    // it found. They must survive the derivation untouched.
    await insertScan(pg, "scan-legacy", { critical: 3, high: 2, medium: 1, low: 0, info: 4 }, "2026-10-25T09:00:00Z");

    const { summaries, error } = await queryScanSummaries(sql);
    assert.equal(error, null);
    assert.deepEqual(countsOf(summaries[0]!), { critical: 3, high: 2, medium: 1, low: 0, info: 4 });

    const { stats } = await queryScansStats(sql);
    assert.equal(stats.total, 1);
    assert.equal(stats.critical, 3);
    assert.equal(stats.high, 2);
  } finally {
    await pg.close();
  }
});

test("stats totals equal the findings counts when every scan has findings rows", async () => {
  const { pg, sql } = await database();
  try {
    await insertScan(pg, "scan-a", { critical: 9, high: 9, medium: 9, low: 9, info: 9 }, "2026-10-25T10:00:00Z");
    await insertFinding(pg, "scan-a", 0, "critical");
    await insertFinding(pg, "scan-a", 1, "critical");
    await insertFinding(pg, "scan-a", 2, "high");
    await insertScan(pg, "scan-b", { critical: 9, high: 9, medium: 9, low: 9, info: 9 }, "2026-10-25T11:00:00Z");
    await insertFinding(pg, "scan-b", 0, "critical");
    await insertFinding(pg, "scan-b", 1, "medium");
    await insertFinding(pg, "scan-b", 2, "medium");
    await insertFinding(pg, "scan-b", 3, "medium");

    const { stats, error } = await queryScansStats(sql);
    assert.equal(error, null);
    assert.equal(stats.total, 2);
    assert.equal(stats.critical, 3);
    assert.equal(stats.high, 1);
  } finally {
    await pg.close();
  }
});

test("mixed archive: stats equal the sum of the per-scan derived counts", async () => {
  const { pg, sql } = await database();
  try {
    await insertScan(pg, "scan-fixed", { critical: 5, high: 5, medium: 5, low: 5, info: 5 }, "2026-10-25T10:00:00Z");
    await insertFinding(pg, "scan-fixed", 0, "critical");
    await insertFinding(pg, "scan-fixed", 1, "critical");
    await insertFinding(pg, "scan-fixed", 2, "high");
    await insertScan(pg, "scan-legacy", { critical: 3, high: 2, medium: 1, low: 0, info: 4 }, "2026-10-25T09:00:00Z");
    await insertScan(pg, "scan-clean", { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, "2026-10-25T08:00:00Z");

    const { summaries, error } = await queryScanSummaries(sql);
    assert.equal(error, null);
    assert.equal(summaries.length, 3);
    const sum = summaries.reduce<StoredCounts>(
      (acc, s) => ({
        critical: acc.critical + s.criticalCount,
        high: acc.high + s.highCount,
        medium: acc.medium + s.mediumCount,
        low: acc.low + s.lowCount,
        info: acc.info + s.infoCount,
      }),
      { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    );
    const { stats } = await queryScansStats(sql);
    assert.equal(stats.total, 3);
    assert.equal(stats.critical, sum.critical);
    assert.equal(stats.high, sum.high);
    assert.equal(stats.critical, 5); // 2 derived + 3 legacy-stored
    assert.equal(stats.high, 3); // 1 derived + 2 legacy-stored
  } finally {
    await pg.close();
  }
});

test("queryDerivedSeverityCounts: entries exist only for scans with findings rows", async () => {
  const { pg, sql } = await database();
  try {
    await insertScan(pg, "scan-fixed", { critical: 5, high: 5, medium: 5, low: 5, info: 5 }, "2026-10-25T10:00:00Z");
    await insertFinding(pg, "scan-fixed", 0, "low");
    await insertScan(pg, "scan-legacy", { critical: 3, high: 2, medium: 1, low: 0, info: 4 }, "2026-10-25T09:00:00Z");

    const derived = await queryDerivedSeverityCounts(sql, ["scan-fixed", "scan-legacy"]);
    assert.deepEqual(derived.get("scan-fixed"), {
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 1,
      infoCount: 0,
    });
    assert.equal(derived.has("scan-legacy"), false);
    assert.deepEqual(await queryDerivedSeverityCounts(sql, []), new Map());
  } finally {
    await pg.close();
  }
});

test("summaries: a failed findings-counts read surfaces as an error, never stored-count silence", async () => {
  const ROW: ScanSummaryRow = {
    id: "scan-1",
    label: "Token",
    input_kind: "address",
    contract_name: "Token",
    target_address: null,
    chain_id: "ethereum",
    proxy_info_json: null,
    probes_json: null,
    cert_hash: null,
    source_origin: "pipeline",
    risk_score: 10,
    critical_count: 7,
    high_count: 7,
    medium_count: 7,
    low_count: 7,
    info_count: 7,
    balance_wei: null,
    value_usd: null,
    unparsed: false,
    analyzer_version: null,
    created_at: "2026-10-25T00:00:00.000Z",
  };
  const sql = createSqlClient(async <T>(text: string) => {
    if (text.includes("from findings")) throw new Error("findings relation exploded");
    return [ROW] as T[];
  });
  const { summaries, error } = await queryScanSummaries(sql);
  assert.deepEqual(summaries, []);
  assert.ok(error && error.includes("findings relation exploded"), `error was: ${error}`);
});

// --- The loadScan seam -------------------------------------------------------
// loadScan (persist.server.ts) builds its header counts from its already
// fetched finding rows via countsFromSeverityList + summaryFromRow — the
// exact calls pinned here — passing no derived counts (stored columns)
// when the scan has no findings rows.

const SEAM_ROW: ScanSummaryRow = {
  id: "scan-1",
  label: "Token",
  input_kind: "address",
  contract_name: "Token",
  risk_score: 10,
  critical_count: 7,
  high_count: 7,
  medium_count: 7,
  low_count: 7,
  info_count: 7,
  created_at: "2026-10-25T00:00:00.000Z",
};

test("loadScan seam: derived counts from the findings list override the stored columns", () => {
  const derived = countsFromSeverityList(["critical", "critical", "high", "info", "info", "info"]);
  const s = summaryFromRow(SEAM_ROW, derived);
  assert.deepEqual(countsOf(s), { critical: 2, high: 1, medium: 0, low: 0, info: 3 });
});

test("loadScan seam: no derived counts (no findings rows) keeps the stored columns", () => {
  const s = summaryFromRow(SEAM_ROW, undefined);
  assert.deepEqual(countsOf(s), { critical: 7, high: 7, medium: 7, low: 7, info: 7 });
});

test("countsFromSeverityList ignores severities with no summary field", () => {
  assert.deepEqual(countsFromSeverityList(["critical", "bogus", ""]), {
    criticalCount: 1,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    infoCount: 0,
  });
});

test("loadScan wiring: persist.server.ts derives the header counts from its finding rows", async () => {
  // Source guard, same pattern as persist-nofallback's db.ts guard:
  // loadScan's Sql is not injectable in this harness, so the wiring is
  // pinned textually and the derivation itself is pinned behaviorally
  // by the seam tests above.
  const source = await readFile(new URL("./persist.server.ts", import.meta.url), "utf8");
  const start = source.indexOf("export async function loadScan");
  const end = source.indexOf("export async function deleteScan");
  assert.ok(start >= 0 && end > start, "loadScan body located");
  const body = source.slice(start, end);
  assert.ok(body.includes("countsFromSeverityList(findingRows"), "loadScan derives counts from findingRows");
  assert.ok(body.includes("summaryFromRow(row, derivedCounts)"), "loadScan passes derived counts to summaryFromRow");
  assert.ok(body.includes("findingRows.length > 0"), "loadScan keeps stored counts when there are no findings rows");
});
