import assert from "node:assert/strict";
import test from "node:test";
import { createSqlClient } from "../sql-client.ts";
import type { Sql } from "../sql-client.ts";
import { savedScanVersions, shouldSkipInRun } from "./scan-freshness.server.ts";

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

test("savedScanVersions unchanged: a key with any current row is never stale", async () => {
  const { sql } = fakeDb([
    { chain_id: "ethereum", addr: A.toLowerCase(), analyzer_version: OLD_STAMP },
    { chain_id: "ethereum", addr: A.toLowerCase(), analyzer_version: STAMP },
  ]);
  const { current, stale } = await savedScanVersions(sql, [item(A)], STAMP);
  assert.equal(current.has(`ethereum:${A.toLowerCase()}`), true);
  assert.equal(stale.has(`ethereum:${A.toLowerCase()}`), false);
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
): Promise<{ analyzed: number; dupes: number }> {
  const seen = new Set<string>();
  let analyzed = 0;
  let dupes = 0;
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
    analyzed++;
    it.status = "completed";
    seen.add(key);
    if (afterItem) await afterItem(idx);
  }
  return { analyzed, dupes };
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
