import assert from "node:assert/strict";
import test from "node:test";
import { createSqlClient } from "../sql-client.ts";
import type { Sql } from "../sql-client.ts";
import { assertFreshnessSchema, savedScanVersions, shouldSkipInRun } from "./scan-freshness.server.ts";

/**
 * In-run dedupe (2026-10-22, improvement #1 narrowed): the worker's
 * per-item re-check. The /start check (savedScanVersions) cannot see
 * rows saved after it ran — a twin later in the same file whose batch
 * has since flushed, or another writer saving the same address mid-run.
 * shouldSkipInRun mirrors the /start refresh-policy mapping and never
 * throws (a dedupe failure means "proceed", never "stall the run").
 *
 * Driven by a fake Sql over a mutable in-memory contract_scans table —
 * no database involved.
 */

const STAMP = "2099-01-01.0+teststamp";
const OLD_STAMP = "2020-01-01.0+oldstamp";

const A = "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa";
const B = "0xBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBb";

type Row = { chain_id: string; addr: string; analyzer_version: string | null };

type Runner = (text: string, params: unknown[]) => Promise<unknown[]>;

function fakeDb(rows: Row[]): { sql: Sql; table: Row[] } {
  const runner: Runner = async (_text, params) => {
    // savedScanVersions' only query: rows whose lower(address) is in
    // the single array parameter — the same shape the real SQL returns.
    const addrs = params[0] as string[];
    return rows.filter((r) => addrs.includes(r.addr));
  };
  const sql = createSqlClient(async <T>(text: string, params: unknown[]) => runner(text, params) as Promise<T[]>);
  return { sql, table: rows };
}

function throwingSql(): Sql {
  return createSqlClient((async () => {
    throw new Error("db is down");
  }) as never);
}

const item = (address: string, chainId = "ethereum") => ({ chainId, address });

// ------------------------------------------------------- policy mapping --

test("shouldSkipInRun: current row skips under stale and none, never under all", async () => {
  const { sql } = fakeDb([{ chain_id: "ethereum", addr: A.toLowerCase(), analyzer_version: STAMP }]);
  assert.equal(await shouldSkipInRun(sql, item(A), "stale", STAMP), true);
  assert.equal(await shouldSkipInRun(sql, item(A), "none", STAMP), true);
  assert.equal(await shouldSkipInRun(sql, item(A), "all", STAMP), false);
});

test("shouldSkipInRun: stale row re-analyzes under stale, counts as done under none", async () => {
  const { sql } = fakeDb([{ chain_id: "ethereum", addr: A.toLowerCase(), analyzer_version: OLD_STAMP }]);
  assert.equal(await shouldSkipInRun(sql, item(A), "stale", STAMP), false);
  assert.equal(await shouldSkipInRun(sql, item(A), "none", STAMP), true);
  assert.equal(await shouldSkipInRun(sql, item(A), "all", STAMP), false);
});

test("shouldSkipInRun: pre-stamp NULL version rows are stale, like /start", async () => {
  const { sql } = fakeDb([{ chain_id: "ethereum", addr: A.toLowerCase(), analyzer_version: null }]);
  assert.equal(await shouldSkipInRun(sql, item(A), "stale", STAMP), false);
  assert.equal(await shouldSkipInRun(sql, item(A), "none", STAMP), true);
});

test("shouldSkipInRun: no row means proceed under every policy; chain must match", async () => {
  const { sql } = fakeDb([{ chain_id: "bsc", addr: A.toLowerCase(), analyzer_version: STAMP }]);
  for (const refresh of ["stale", "none", "all"]) {
    assert.equal(await shouldSkipInRun(sql, item(A), refresh, STAMP), false, refresh);
  }
  // Same address on the chain the row belongs to DOES match.
  assert.equal(await shouldSkipInRun(sql, item(A, "bsc"), "stale", STAMP), true);
});

test("shouldSkipInRun: a failing check fails open (proceed), under every policy", async () => {
  for (const refresh of ["stale", "none", "all"]) {
    assert.equal(await shouldSkipInRun(throwingSql(), item(A), refresh, STAMP), false, refresh);
  }
});

test("savedScanVersions: current rows classify current; stale and NULL rows classify stale", async () => {
  const B_LOWER = B.toLowerCase();
  const { sql } = fakeDb([
    { chain_id: "ethereum", addr: A.toLowerCase(), analyzer_version: STAMP },
    { chain_id: "ethereum", addr: B_LOWER, analyzer_version: OLD_STAMP },
    { chain_id: "ethereum", addr: "0xcccc", analyzer_version: null },
  ]);
  const { current, stale } = await savedScanVersions(
    sql,
    [item(A), item(B), item("0xCCCC")],
    STAMP,
  );
  assert.deepEqual([...current], [`ethereum:${A.toLowerCase()}`]);
  assert.deepEqual(
    [...stale].sort(),
    [`ethereum:${B_LOWER}`, "ethereum:0xcccc"],
  );
});

test("savedScanVersions: a row stamped with the pre-ResNet stamp is stale, never current", async () => {
  // The literal stamp the analyzer wrote before the ResNet batch
  // (baseline 2026-10-23.1; derivation pinned in analyzer-version.test).
  // Rows carrying it were never screened and their scores lack the ML
  // term — the /start classification must route them to re-analysis.
  const PRE_RESNET = "2026-10-23.1+26069e703d4873b4";
  const { sql } = fakeDb([{ chain_id: "ethereum", addr: A.toLowerCase(), analyzer_version: PRE_RESNET }]);
  const { current, stale } = await savedScanVersions(sql, [item(A)], STAMP);
  assert.equal(current.size, 0);
  assert.deepEqual([...stale], [`ethereum:${A.toLowerCase()}`]);
});

test("savedScanVersions: chain case never splits a key (stored 'Ethereum' matches wanted 'ethereum')", async () => {
  // Regression: keys were built from the raw stored chain_id, so a row
  // saved under a case variant produced key "Ethereum:0x…" and the
  // worker's wanted key "ethereum:0x…" never matched — the current row
  // was invisible to the skip check and re-analyzed on every run.
  const { sql } = fakeDb([{ chain_id: "Ethereum", addr: A.toLowerCase(), analyzer_version: STAMP }]);
  const { current } = await savedScanVersions(sql, [item(A)], STAMP);
  assert.deepEqual([...current], [`ethereum:${A.toLowerCase()}`]);
  // And the mirror image through the in-run check: wanted in a case
  // variant, stored canonical.
  const { sql: sql2 } = fakeDb([{ chain_id: "ethereum", addr: A.toLowerCase(), analyzer_version: STAMP }]);
  assert.equal(await shouldSkipInRun(sql2, item(A, "Ethereum"), "stale", STAMP), true);
});

test("savedScanVersions unchanged: a key with any current row is never stale", async () => {
  const { sql } = fakeDb([
    { chain_id: "ethereum", addr: A.toLowerCase(), analyzer_version: OLD_STAMP },
    { chain_id: "ethereum", addr: A.toLowerCase(), analyzer_version: STAMP },
  ]);
  const { current, stale } = await savedScanVersions(sql, [item(A)], STAMP);
  assert.equal(current.has(`ethereum:${A.toLowerCase()}`), true);
  assert.equal(stale.has(`ethereum:${A.toLowerCase()}`), false);
});

// ------------------------------------------------------ schema preflight --
// assertFreshnessSchema gates /start on the columns a run actually
// reads/writes: analyzer_version (0014, the skip itself), findings'
// corroborated (0016, every bulk save), resnet_json (0018, every bulk
// save). The original gate checked only 0014 — a pre-0016/0018 database
// passed it and then failed every flush with a raw column error.

function fakeSchema(present: string[]): Sql {
  const rows = present.map((p) => {
    const [table_name, column_name] = p.split(".") as [string, string];
    return { table_name, column_name };
  });
  return createSqlClient((async () => rows) as never);
}

const ALL_SCHEMA = [
  "contract_scans.analyzer_version",
  "findings.corroborated",
  "contract_scans.resnet_json",
  // 0012_finding_triage — bulk-persist writes all seven on every save.
  "findings.family",
  "findings.reachability",
  "findings.gate",
  "findings.preconditions",
  "findings.confidence_basis",
  "findings.economic_figure",
  "findings.economic_basis",
];

test("assertFreshnessSchema: passes when every required column exists", async () => {
  await assertFreshnessSchema(fakeSchema(ALL_SCHEMA));
});

test("assertFreshnessSchema: a missing triage column fails the gate, naming 0012", async () => {
  // Without these every bulk save throws on the first flush — 50,000 findings
  // into a queue with nothing written. /start must refuse instead.
  for (const column of ["family", "reachability", "preconditions", "economic_basis"]) {
    await assert.rejects(
      assertFreshnessSchema(fakeSchema(ALL_SCHEMA.filter((c) => c !== `findings.${column}`))),
      new RegExp(`${column}.*migration 0012_finding_triage`),
    );
  }
});

test("assertFreshnessSchema: a missing post-0014 column fails the gate, naming its migration", async () => {
  await assert.rejects(
    assertFreshnessSchema(fakeSchema(ALL_SCHEMA.filter((c) => c !== "contract_scans.resnet_json"))),
    /resnet_json.*migration 0018/,
  );
  await assert.rejects(
    assertFreshnessSchema(fakeSchema(ALL_SCHEMA.filter((c) => c !== "findings.corroborated"))),
    /corroborated.*migration 0016/,
  );
});

test("assertFreshnessSchema: the original 0014 check still fires (message preserved in substance)", async () => {
  await assert.rejects(
    assertFreshnessSchema(fakeSchema(ALL_SCHEMA.filter((c) => c !== "contract_scans.analyzer_version"))),
    /analyzer_version.*migration 0014 not applied/,
  );
  // Nothing present: every missing column is named in one error.
  await assert.rejects(assertFreshnessSchema(fakeSchema([])), /0014.*0016.*0018/s);
});

// ------------------------------------------------------ loop simulation --
// Mirrors runLoop's per-item decision order exactly: start-time skip
// (pre-marked "skipped") → in-run seen set → per-item DB re-check →
// analyze. Analyzing does NOT insert into the fake table (the worker's
// saves flush in batches; a record is not in the DB when its twin is
// reached) — external writers are modeled by the afterItem hook.

type SimItem = { chainId: string; address: string; status: string };

async function simulate(
  items: SimItem[],
  refresh: string,
  sql: Sql,
  afterItem?: (index: number) => void | Promise<void>,
  opts?: { failOnce?: Set<string> },
): Promise<{ analyzed: number; dupes: number; attempts: number }> {
  const seen = new Set<string>();
  let analyzed = 0;
  let dupes = 0;
  let attempts = 0;
  for (let idx = 0; idx < items.length; idx++) {
    const it = items[idx]!;
    if (it.status === "skipped") continue;
    const key = `${it.chainId}:${it.address.toLowerCase()}`;
    if (seen.has(key)) {
      it.status = "skipped";
      dupes++;
      continue;
    }
    if (refresh !== "all" && (await shouldSkipInRun(sql, it, refresh, STAMP))) {
      seen.add(key);
      it.status = "skipped";
      dupes++;
      continue;
    }
    attempts++;
    // A failed analysis (worker.ts catch path): the item counts as
    // failed, the index advances, and the key is deliberately NOT added
    // to the seen set — a later twin still gets its own attempt.
    if (opts?.failOnce?.has(key)) {
      opts.failOnce.delete(key);
      it.status = "failed";
      continue;
    }
    analyzed++;
    it.status = "completed";
    seen.add(key);
    if (afterItem) await afterItem(idx);
  }
  return { analyzed, dupes, attempts };
}

const simItem = (address: string): SimItem => ({ chainId: "ethereum", address, status: "pending" });

test("loop: twin address in one file is analyzed once, saved once, twin skipped", async () => {
  const { sql } = fakeDb([]);
  const items = [simItem(A), simItem(B), simItem(A.toUpperCase().replace("0X", "0x"))];
  const { analyzed, dupes } = await simulate(items, "stale", sql);
  assert.equal(analyzed, 2);
  assert.equal(dupes, 1);
  assert.equal(items[2]!.status, "skipped");
});

test("loop: a row saved concurrently mid-run skips the item when reached", async () => {
  const { sql, table } = fakeDb([]);
  const items = [simItem(A), simItem(B)];
  const { analyzed, dupes } = await simulate(items, "stale", sql, (idx) => {
    if (idx === 0) {
      // The browser pipeline saves B while this run is between items.
      table.push({ chain_id: "ethereum", addr: B.toLowerCase(), analyzer_version: STAMP });
    }
  });
  assert.equal(analyzed, 1);
  assert.equal(dupes, 1);
  assert.equal(items[1]!.status, "skipped");
});

test("loop: a stale row appearing mid-run is still re-analyzed (refresh=stale)", async () => {
  const { sql, table } = fakeDb([]);
  const items = [simItem(A), simItem(B)];
  const { analyzed, dupes } = await simulate(items, "stale", sql, (idx) => {
    if (idx === 0) table.push({ chain_id: "ethereum", addr: B.toLowerCase(), analyzer_version: OLD_STAMP });
  });
  assert.equal(analyzed, 2);
  assert.equal(dupes, 0);
});

test("loop: refresh=all — DB rows never skip, but the seen set still dedupes twins", async () => {
  const { sql } = fakeDb([{ chain_id: "ethereum", addr: A.toLowerCase(), analyzer_version: STAMP }]);
  const items = [simItem(A), simItem(A)];
  const { analyzed, dupes } = await simulate(items, "all", sql);
  assert.equal(analyzed, 1); // A re-analyzed despite the saved row…
  assert.equal(dupes, 1); // …but its twin is not done twice in one run
  assert.equal(items[1]!.status, "skipped");
});

test("loop: a throwing check fails open — the item is processed", async () => {
  const items = [simItem(A)];
  const { analyzed, dupes } = await simulate(items, "stale", throwingSql());
  assert.equal(analyzed, 1);
  assert.equal(dupes, 0);
  assert.equal(items[0]!.status, "completed");
});

test("loop: a FAILED item is not deduped — its twin gets its own attempt", async () => {
  // The worker's failure path (non-RPC analyze error) advances the
  // index without adding the key to runSeen, so a twin later in the
  // file is a fresh attempt, not a dupe. (An RpcUnavailableError is the
  // opposite case — it parks the run with the index NOT advanced; that
  // path lives in worker.ts and is not part of this simulation.)
  const { sql } = fakeDb([]);
  const items = [simItem(A), simItem(A.toLowerCase())];
  const key = `ethereum:${A.toLowerCase()}`;
  const { analyzed, dupes, attempts } = await simulate(items, "stale", sql, undefined, {
    failOnce: new Set([key]),
  });
  assert.equal(attempts, 2);
  assert.equal(analyzed, 1);
  assert.equal(dupes, 0);
  assert.equal(items[0]!.status, "failed");
  assert.equal(items[1]!.status, "completed");
});

test("loop: cross-chain twins are independent — neither dedupes the other", async () => {
  const { sql } = fakeDb([]);
  const items: SimItem[] = [
    { chainId: "ethereum", address: A, status: "pending" },
    { chainId: "bsc", address: A, status: "pending" },
  ];
  const { analyzed, dupes } = await simulate(items, "stale", sql);
  assert.equal(analyzed, 2);
  assert.equal(dupes, 0);
});
