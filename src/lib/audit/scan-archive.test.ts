import assert from "node:assert/strict";
import test from "node:test";
import { createSqlClient } from "../sql-client.ts";
import type { Sql } from "../sql-client.ts";
import {
  queryDatabaseSize,
  queryScanSummaries,
  queryScansStats,
  type ScanSummaryRow,
} from "./scan-archive.server.ts";

/**
 * Archive read queries (2026-10-22, improvements #2 + #3): a failed query
 * returns an error payload instead of a silent [] / zeros; the size reader
 * fails soft. Driven by a fake Sql (createSqlClient over a stub runner) —
 * no database involved.
 */

type Runner = (text: string, params: unknown[]) => Promise<unknown[]>;

function fakeSql(runner: Runner): Sql {
  return createSqlClient(async <T>(text: string, params: unknown[]) => runner(text, params) as Promise<T[]>);
}

const ROW: ScanSummaryRow = {
  id: "scan-1",
  label: "Token",
  input_kind: "address",
  contract_name: "Token",
  target_address: "0x0000000000000000000000000000000000000001",
  chain_id: "ethereum",
  proxy_info_json: JSON.stringify({ isProxy: true }),
  probes_json: JSON.stringify([{}, {}]),
  cert_hash: "abc",
  source_origin: "pipeline",
  is_rag_indexed: true,
  risk_score: 88,
  critical_count: 1,
  high_count: 2,
  medium_count: 3,
  low_count: 4,
  info_count: 5,
  balance_wei: "1000",
  value_usd: 42.5,
  unparsed: false,
  analyzer_version: "2026-10-21.1+deadbeefcafebabe",
  created_at: "2026-10-22T00:00:00.000Z",
};

test("queryScanSummaries maps rows and reports no error on success", async () => {
  const sql = fakeSql(async () => [ROW]);
  const { summaries, error } = await queryScanSummaries(sql, { limit: 60, offset: 0 });
  assert.equal(error, null);
  assert.equal(summaries.length, 1);
  const s = summaries[0]!;
  assert.equal(s.id, "scan-1");
  assert.equal(s.contractName, "Token");
  assert.equal(s.riskScore, 88);
  assert.equal(s.hasProxy, true);
  assert.equal(s.probesCount, 2);
  assert.equal(s.isRagIndexed, true);
  assert.equal(s.valueUsd, 42.5);
  assert.equal(s.analyzerVersion, "2026-10-21.1+deadbeefcafebabe");
});

test("queryScanSummaries clamps limit/offset before querying", async () => {
  let captured: unknown[] = [];
  const sql = fakeSql(async (_text, params) => {
    captured = params;
    return [];
  });
  const { summaries, error } = await queryScanSummaries(sql, { limit: 9999, offset: -5 });
  assert.equal(error, null);
  assert.deepEqual(summaries, []);
  assert.deepEqual(captured, [500, 0]);
});

test("queryScanSummaries surfaces a query failure as an error payload, never a silent []", async () => {
  const sql = fakeSql(async () => {
    throw new Error('relation "contract_scans" does not exist');
  });
  const { summaries, error } = await queryScanSummaries(sql);
  assert.deepEqual(summaries, []);
  assert.ok(error && error.includes("does not exist"), `error was: ${error}`);
});

test("queryScansStats parses the aggregate row", async () => {
  const sql = fakeSql(async () => [{ total: "2553", critical: "18", high: "2974", rag_indexed: "2543" }]);
  const { stats, error } = await queryScansStats(sql);
  assert.equal(error, null);
  assert.deepEqual(stats, { total: 2553, critical: 18, high: 2974, ragIndexed: 2543 });
});

test("queryScansStats surfaces a failure instead of silent zeros", async () => {
  const sql = fakeSql(async () => {
    throw new Error("connection terminated");
  });
  const { stats, error } = await queryScansStats(sql);
  assert.deepEqual(stats, { total: 0, critical: 0, high: 0, ragIndexed: 0 });
  assert.ok(error && error.includes("connection terminated"), `error was: ${error}`);
});

test("queryDatabaseSize returns the total and the largest tables parsed as numbers", async () => {
  const sql = fakeSql(async (text) => {
    if (text.includes("pg_database_size")) return [{ total_bytes: "605552640" }];
    return [
      { name: "rag_knowledge_chunks", bytes: "209715200" },
      { name: "fourbyte_signatures", bytes: "136314880" },
      { name: "contract_scans", bytes: "52428800" },
    ];
  });
  const { totalBytes, tables, error } = await queryDatabaseSize(sql);
  assert.equal(error, null);
  assert.equal(totalBytes, 605552640);
  assert.deepEqual(tables, [
    { name: "rag_knowledge_chunks", bytes: 209715200 },
    { name: "fourbyte_signatures", bytes: 136314880 },
    { name: "contract_scans", bytes: 52428800 },
  ]);
});

test("queryDatabaseSize fails soft when the size read fails", async () => {
  const sql = fakeSql(async () => {
    throw new Error("permission denied for database");
  });
  const result = await queryDatabaseSize(sql);
  assert.equal(result.totalBytes, null);
  assert.deepEqual(result.tables, []);
  assert.ok(result.error && result.error.includes("permission denied"), `error was: ${result.error}`);
});

test("queryDatabaseSize keeps the total when only the per-table breakdown fails", async () => {
  const sql = fakeSql(async (text) => {
    if (text.includes("pg_database_size")) return [{ total_bytes: "1048576" }];
    throw new Error("pg_class unreadable");
  });
  const result = await queryDatabaseSize(sql);
  assert.equal(result.totalBytes, 1048576);
  assert.deepEqual(result.tables, []);
  assert.ok(result.error && result.error.includes("pg_class"), `error was: ${result.error}`);
});

// --- No-fallback / degrade contract (2026-10-22 rework) ---------------------

test("an empty archive is an EXPLICIT empty: no error, no warning, state remote", async () => {
  // Genuinely empty must stay distinguishable from failure: the payload
  // says "remote + zero rows", which the UI renders as an empty archive
  // naming the database — never conflated with a failed read.
  const listSql = fakeSql(async () => []);
  const list = await queryScanSummaries(listSql);
  assert.equal(list.error, null);
  assert.equal(list.warning, null);
  assert.equal(list.dbState, "remote");
  assert.deepEqual(list.summaries, []);

  const statsSql = fakeSql(async (text) =>
    text.includes("is_rag_indexed") ? [{ rag_indexed: "0" }] : [{ total: "0", critical: "0", high: "0" }],
  );
  const stats = await queryScansStats(statsSql);
  assert.equal(stats.error, null);
  assert.equal(stats.dbState, "remote");
  assert.deepEqual(stats.stats, { total: 0, critical: 0, high: 0, ragIndexed: 0 });
});

test("missing drift columns degrade the summaries read instead of zeroing it", async () => {
  // The archive predates migrations 0012/0014: value_usd and
  // analyzer_version are absent. The full select throws; the reader must
  // introspect, retry with the columns that exist, return partial rows
  // (absent fields nulled), and name the missing columns in the warning.
  const PRESENT = [
    "id", "label", "input_kind", "contract_name", "target_address", "chain_id",
    "proxy_info_json", "probes_json", "cert_hash", "source_origin", "is_rag_indexed",
    "risk_score", "critical_count", "high_count", "medium_count", "low_count",
    "info_count", "balance_wei", "unparsed", "created_at",
  ];
  const partialRow = { ...ROW } as Record<string, unknown>;
  delete partialRow.analyzer_version;
  delete partialRow.value_usd;
  const sql = fakeSql(async (text) => {
    if (text.includes("information_schema")) return PRESENT.map((c) => ({ column_name: c }));
    if (text.includes("analyzer_version")) throw new Error('column "analyzer_version" does not exist');
    return [partialRow];
  });
  const { summaries, error, warning } = await queryScanSummaries(sql);
  assert.equal(error, null);
  assert.equal(summaries.length, 1);
  assert.equal(summaries[0]!.analyzerVersion, null);
  assert.equal(summaries[0]!.valueUsd, null);
  assert.ok(warning && warning.includes("analyzer_version"), `warning was: ${warning}`);
  assert.ok(warning && warning.includes("value_usd"), `warning was: ${warning}`);
});

test("stats and list fail independently — one bad query never zeroes the other", async () => {
  // Stats broken, list healthy: list data intact.
  const goodList = fakeSql(async () => [ROW]);
  const list = await queryScanSummaries(goodList);
  assert.equal(list.error, null);
  assert.equal(list.summaries.length, 1);
  const badStats = fakeSql(async () => {
    throw new Error("stats relation gone");
  });
  const statsFail = await queryScansStats(badStats);
  assert.ok(statsFail.error && statsFail.error.includes("stats relation gone"));

  // List broken, stats healthy: stats intact.
  const badList = fakeSql(async () => {
    throw new Error("list relation gone");
  });
  const listFail = await queryScanSummaries(badList);
  assert.deepEqual(listFail.summaries, []);
  assert.ok(listFail.error && listFail.error.includes("list relation gone"));
  const goodStats = fakeSql(async (text) =>
    text.includes("is_rag_indexed") ? [{ rag_indexed: "7" }] : [{ total: "9", critical: "1", high: "2" }],
  );
  const stats = await queryScansStats(goodStats);
  assert.equal(stats.error, null);
  assert.deepEqual(stats.stats, { total: 9, critical: 1, high: 2, ragIndexed: 7 });
});

test("a failed RAG count degrades to a warning — headline totals stay intact", async () => {
  const sql = fakeSql(async (text) => {
    if (text.includes("is_rag_indexed")) throw new Error('column "is_rag_indexed" does not exist');
    return [{ total: "8931", critical: "18", high: "2974" }];
  });
  const { stats, error, warning } = await queryScansStats(sql);
  assert.equal(error, null);
  assert.deepEqual(stats, { total: 8931, critical: 18, high: 2974, ragIndexed: 0 });
  assert.ok(warning && warning.includes("RAG"), `warning was: ${warning}`);
});
