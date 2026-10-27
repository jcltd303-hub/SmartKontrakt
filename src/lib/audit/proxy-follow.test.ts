import test from "node:test";
import assert from "node:assert/strict";

import { dedupeKey, implementationItems } from "../../../pipeline-worker/proxy-follow.ts";

/**
 * Following a proxy to its implementation (2026-10-27).
 *
 * The gap this closes: detectProxyArchitecture returned the implementation
 * addresses, they were persisted and mentioned in the report, and nothing ever
 * analysed them — so a proxy was judged on its delegatecall shell.
 */

const PROXY = "0x1111111111111111111111111111111111111111";
const IMPL = "0x2222222222222222222222222222222222222222";
const IMPL2 = "0x3333333333333333333333333333333333333333";

test("each implementation becomes a pending queue entry on the same chain", () => {
  const items = implementationItems({ implementations: [IMPL, IMPL2] }, "ethereum", new Set());
  assert.equal(items.length, 2);
  assert.equal(items[0]!.address, IMPL);
  assert.equal(items[0]!.chainId, "ethereum");
  assert.equal(items[0]!.status, "pending");
  assert.match(items[0]!.label, /Implementation of proxy/);
});

test("an address already queued is not queued twice", () => {
  const seen = new Set([dedupeKey("ethereum", IMPL)]);
  const items = implementationItems({ implementations: [IMPL, IMPL2] }, "ethereum", seen);
  assert.deepEqual(items.map((i) => i.address), [IMPL2]);
});

test("the same implementation on another chain is a separate entry", () => {
  const seen = new Set([dedupeKey("ethereum", IMPL)]);
  const items = implementationItems({ implementations: [IMPL] }, "base", seen);
  assert.equal(items.length, 1, "chain is part of the identity, as everywhere else");
});

test("the zero address is never followed", () => {
  // A failed implementation read returns the zero address; analysing it would
  // throw "No deployed bytecode found" and burn a queue slot.
  const items = implementationItems(
    { implementations: ["0x0000000000000000000000000000000000000000", IMPL] },
    "ethereum",
    new Set(),
  );
  assert.deepEqual(items.map((i) => i.address), [IMPL]);
});

test("duplicates inside one implementation list collapse", () => {
  const items = implementationItems({ implementations: [IMPL, IMPL.toUpperCase()] }, "ethereum", new Set());
  assert.equal(items.length, 1);
});

test("junk shapes are ignored rather than thrown on", () => {
  for (const info of [null, undefined, {}, { implementations: null }, { implementations: "x" }, { implementations: [1, "", "0xzz"] }]) {
    assert.deepEqual(implementationItems(info as never, "ethereum", new Set()), []);
  }
});

test("a proxy with no implementations yields nothing", () => {
  assert.deepEqual(implementationItems({ implementations: [] }, "ethereum", new Set()), []);
});
