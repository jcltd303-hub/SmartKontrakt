import test from "node:test";
import assert from "node:assert/strict";

import { RpcPool, parseRpcUrls } from "./rpc-endpoints.ts";

/**
 * Pluggable RPC endpoints (2026-10-27).
 *
 * The analysis path had no RPC configuration: every call walked a hardcoded list
 * from the top, so a keyed provider could not be plugged in and a rate-limited
 * endpoint at position 0 was retried first forever.
 */

const A = "https://a.example/v1";
const B = "https://b.example/v1";
const C = "https://c.example/v1";

test("RPC_URLS parses a comma list, with optional chain prefixes", () => {
  const parsed = parseRpcUrls(` ${A} , ethereum:${B} ,, ${C} `);
  assert.deepEqual(parsed, [
    { url: A, chain: null },
    { url: B, chain: "ethereum" },
    { url: C, chain: null },
  ]);
});

test("junk and duplicates are dropped, not thrown on", () => {
  assert.deepEqual(parseRpcUrls(undefined), []);
  assert.deepEqual(parseRpcUrls("   "), []);
  assert.deepEqual(parseRpcUrls("not-a-url,ftp://x"), []);
  assert.equal(parseRpcUrls(`${A},${A}`).length, 1);
});

test("with no configuration the built-in list is untouched", () => {
  const pool = new RpcPool([]);
  const builtIn = ["https://public-1", "https://public-2"];
  assert.deepEqual(pool.order("ethereum", builtIn), builtIn);
});

test("configured endpoints come first, then the built-ins as fallback", () => {
  const pool = new RpcPool(parseRpcUrls(`${A},${B}`));
  const order = pool.order("ethereum", ["https://public-1"]);
  assert.deepEqual(order, [A, B, "https://public-1"]);
});

test("rotation shares load across providers instead of always starting at the first", () => {
  const pool = new RpcPool(parseRpcUrls(`${A},${B},${C}`));
  const firsts = [0, 1, 2, 3].map(() => pool.order("ethereum", [])[0]);
  assert.deepEqual(firsts, [A, B, C, A], "round-robin, and it wraps");
});

test("a spent endpoint (429/402) goes to the back and is not retried first", () => {
  let clock = 1_000;
  const pool = new RpcPool(parseRpcUrls(`${A},${B}`), () => clock);
  pool.note(A, { ok: false, status: 429 });
  assert.ok(pool.cooldownRemainingMs(A) > 0);
  assert.deepEqual(pool.order("ethereum", []), [B, A], "A is cooling, so B leads");
  clock += 61_000;
  assert.equal(pool.cooldownRemainingMs(A), 0, "the cooldown expires");
  const order = pool.order("ethereum", []);
  assert.ok(order.includes(A));
});

test("a success clears a cooldown", () => {
  const pool = new RpcPool(parseRpcUrls(`${A},${B}`));
  pool.note(A, { ok: false, status: 503 });
  assert.ok(pool.cooldownRemainingMs(A) > 0);
  pool.note(A, { ok: true });
  assert.equal(pool.cooldownRemainingMs(A), 0);
});

test("a network error cools briefly; a 404 does not cool at all", () => {
  const pool = new RpcPool(parseRpcUrls(`${A},${B}`));
  pool.note(A, { ok: false });
  assert.ok(pool.cooldownRemainingMs(A) > 0, "timeout/connection error is transient");
  pool.note(B, { ok: false, status: 404 });
  assert.equal(pool.cooldownRemainingMs(B), 0, "the request was wrong, not the endpoint");
});

test("chain-scoped endpoints only serve their chain, unscoped serve all", () => {
  const pool = new RpcPool(parseRpcUrls(`${A},base:${B}`));
  assert.deepEqual(pool.order("ethereum", []), [A]);
  const baseOrder = pool.order("base", []);
  assert.deepEqual(baseOrder.slice().sort(), [A, B].sort());
});

test("if everything is cooling, the cooling list is still returned", () => {
  const pool = new RpcPool(parseRpcUrls(`${A},${B}`));
  pool.note(A, { ok: false, status: 402 });
  pool.note(B, { ok: false, status: 402 });
  const order = pool.order("ethereum", []);
  assert.equal(order.length, 2, "better to try a spent endpoint than none");
});
