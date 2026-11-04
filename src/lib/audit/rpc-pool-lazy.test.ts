import test from "node:test";
import assert from "node:assert/strict";
import { RpcPool, parseRpcUrls } from "./rpc-endpoints";

test("a pool built before the env was populated still picks it up", () => {
  // The worker builds this at import time, before dotenv loads, so RPC_URLS is undefined.
  // Measured 2026-11-04: the banner said "RPC_URLS set, 1 configured" while the ordered
  // list held only public fallbacks.
  const built = new RpcPool(parseRpcUrls(undefined));
  assert.deepEqual(built.order("ethereum", ["https://public.example"]), ["https://public.example"]);

  process.env.RPC_URLS = "https://eth-mainnet.g.alchemy.com/v2/TESTKEY";
  const ordered = built.order("ethereum", ["https://public.example"]);
  assert.equal(ordered[0], "https://eth-mainnet.g.alchemy.com/v2/TESTKEY", "configured endpoint must lead");
  assert.ok(ordered.includes("https://public.example"), "built-ins stay as fallback");
  delete process.env.RPC_URLS;
});

test("an already-populated pool is unaffected", () => {
  const p = new RpcPool(parseRpcUrls("https://configured.example"));
  const o = p.order("ethereum", ["https://public.example"]);
  assert.equal(o[0], "https://configured.example");
});
