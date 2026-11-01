import test from "node:test";
import assert from "node:assert/strict";

import {
  addressFromStorageWord,
  dedupeKey,
  implementationItems,
  implementationsFromBytecode,
} from "../../../pipeline-worker/proxy-follow.ts";

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

test("an EIP-1167 clone's implementation is read from its bytecode", () => {
  // 47.8 ETH sat behind MinimalProxies scored 2/100 "Clean" on 2026-10-31: the shell has
  // nothing to flag, and the implementation was never queued because the registry
  // reported none. The address is in the code.
  const impl = "1234567890abcdef1234567890abcdef12345678";
  const canonical = `0x363d3d373d3d3d363d73${impl}5af43d82803e903d91602b57fd5bf3`;
  assert.deepEqual(implementationsFromBytecode(canonical), [`0x${impl}`]);

  const oldVariant = `0x3d3d3d3d363d73${impl}5af43d3d93803e602a57fd5bf3`;
  assert.deepEqual(implementationsFromBytecode(oldVariant), [`0x${impl}`]);
});

test("a real contract body yields no implementation", () => {
  const body = "0x608060405234801561001057600080fd5b50" + "ab".repeat(400);
  assert.deepEqual(implementationsFromBytecode(body), []);
  assert.deepEqual(implementationsFromBytecode(null), []);
  assert.deepEqual(implementationsFromBytecode(""), []);
});

test("bytecode-derived implementations are queued alongside registry ones", () => {
  const impl = "1234567890abcdef1234567890abcdef12345678";
  const clone = `0x363d3d373d3d3d363d73${impl}5af43d82803e903d91602b57fd5bf3`;
  // Registry empty — the case that lost the 32 ETH.
  const only = implementationItems({ implementations: [] }, "ethereum", new Set(), clone);
  assert.equal(only.length, 1);
  assert.equal(only[0]!.address, `0x${impl}`);

  // Registry and bytecode agree — no duplicate queue entry.
  const both = implementationItems({ implementations: [`0x${impl}`] }, "ethereum", new Set(), clone);
  assert.equal(both.length, 1);
});

test("a storage word yields an address, and a zero word yields null", () => {
  const impl = "1234567890abcdef1234567890abcdef12345678";
  assert.equal(addressFromStorageWord(`0x${"0".repeat(24)}${impl}`), `0x${impl}`);
  assert.equal(addressFromStorageWord(`0x${"0".repeat(64)}`), null);
  assert.equal(addressFromStorageWord(null), null);
});
