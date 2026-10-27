import test from "node:test";
import assert from "node:assert/strict";

import { findingsQueue } from "./findings-queue.server.ts";
import { createSqlClient } from "../sql-client.ts";

/**
 * The read queue as data (2026-10-27).
 *
 * triage.ts computed the banding and had no consumer: the queue existed, was
 * tested, and was never surfaced. This pins the server-side shape a view reads.
 */

type Row = Record<string, unknown>;

function fakeSql(rows: Row[]) {
  return createSqlClient((async () => rows) as never);
}

const row = (over: Row = {}): Row => ({
  scan_id: "s1",
  target_address: "0x1111111111111111111111111111111111111111",
  chain_id: "ethereum",
  detector: "unprotected-ether",
  family: "caller-identity",
  severity: "high",
  confidence: "high",
  confidence_basis: "resolved site",
  reachability: "REACHABLE",
  gate: null,
  preconditions: [],
  economic_figure: null,
  economic_basis: null,
  title: "sweep sends ether with no access check",
  location_fn: "sweep",
  location_line: 12,
  snippet: "",
  ...over,
});

test("a reachable finding is read-now, and the row carries the reason", async () => {
  const r = await findingsQueue(fakeSql([row()]), 50);
  assert.equal(r.rows.length, 1);
  assert.equal(r.rows[0]!.band, "read-now");
  assert.match(r.rows[0]!.reason, /reachable/);
  assert.equal(r.rows[0]!.address, "0x1111111111111111111111111111111111111111");
  assert.equal(r.counts.readNow, 1);
});

test("gated findings are counted but not queued", async () => {
  const r = await findingsQueue(
    fakeSql([
      row({ reachability: "REACHABLE" }),
      row({ detector: "selfdestruct", reachability: "GATED", gate: "onlyOwner", severity: "high" }),
    ]),
    50,
  );
  assert.equal(r.rows.length, 1, "only the reachable one is a queue entry");
  assert.equal(r.counts.background, 1);
  assert.equal(r.counts.total, 2);
});

test("a low-confidence reachable finding lands in read-next, not read-now", async () => {
  const r = await findingsQueue(fakeSql([row({ confidence: "low", confidence_basis: "loosened gate" })]), 50);
  assert.equal(r.rows[0]!.band, "read-next");
  assert.equal(r.counts.readNext, 1);
  assert.equal(r.counts.readNow, 0);
});

test("a stored jsonb string for preconditions is parsed, not thrown on", async () => {
  const r = await findingsQueue(fakeSql([row({ preconditions: '["holds token","not paused"]' })]), 50);
  assert.equal(r.rows.length, 1);
});

test("a money figure with an assumption basis needs live state, not a read", async () => {
  const r = await findingsQueue(
    fakeSql([row({ reachability: "REACHABLE", economic_figure: "30.8 ETH", economic_basis: "assumption" })]),
    50,
  );
  assert.equal(r.rows[0]!.band, "needs-live-state");
  assert.match(r.rows[0]!.reason, /assumption/);
});

test("an empty archive yields an empty queue, not a throw", async () => {
  const r = await findingsQueue(fakeSql([]), 50);
  assert.deepEqual(r.rows, []);
  assert.equal(r.counts.total, 0);
  assert.equal(r.scanned, 0);
});
