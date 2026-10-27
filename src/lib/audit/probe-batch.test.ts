import test from "node:test";
import assert from "node:assert/strict";

import { executeEthCallBatch, probeContractInterfaces } from "./simulator.ts";

/**
 * JSON-RPC batching for the interface probes (2026-10-27).
 *
 * The seven probes are independent eth_calls to the same endpoint and each was its
 * own POST — 7 of the ~12 round trips an address costs, the largest single group.
 * A batch makes it one. Providers charge the calls as calls; the win is round
 * trips, which is what a "faster HTTP layer in Go/Rust" would have been bought for.
 */

const ADDRESS = "0x1111111111111111111111111111111111111111";

function stubFetch(handler: (body: unknown) => { status?: number; json: unknown }) {
  const requests: unknown[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    requests.push(body);
    const { status = 200, json } = handler(body);
    return new Response(JSON.stringify(json), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return { requests, restore: () => { globalThis.fetch = original; } };
}

test("seven probes leave as one HTTP request", async () => {
  const stub = stubFetch((body) => {
    const batch = Array.isArray(body) ? body : [body];
    return {
      json: batch.map((c: { id: number }) => ({
        jsonrpc: "2.0",
        id: c.id,
        // name() returns a string word; the rest revert, which is the normal case
        result: c.id === 1 ? `0x${"0".repeat(62)}20` : "0x",
      })),
    };
  });
  try {
    const results = await probeContractInterfaces(ADDRESS, "ethereum");
    assert.equal(stub.requests.length, 1, "one request for seven probes");
    assert.ok(Array.isArray(stub.requests[0]), "and it is a JSON-RPC batch");
    assert.equal((stub.requests[0] as unknown[]).length, 7);
    assert.equal(results.length, 7);
    assert.equal(results[0]!.success, true);
    assert.equal(results[0]!.name, "name()");
  } finally {
    stub.restore();
  }
});

test("an endpoint that refuses a batch still gets probed, one call at a time", async () => {
  // Some endpoints answer a batch with a single object rather than an array.
  const stub = stubFetch((body) =>
    Array.isArray(body)
      ? { json: { error: { message: "batch not supported" } } }
      : { json: { jsonrpc: "2.0", id: 1, result: "0x" } },
  );
  try {
    const results = await probeContractInterfaces(ADDRESS, "ethereum");
    assert.ok(stub.requests.length > 1, "it fell back to individual calls");
    assert.equal(results.length, 7, "and every probe still reported");
    assert.ok(results.every((r) => !r.success), "all reverted, which is honest");
  } finally {
    stub.restore();
  }
});

test("a partial batch is treated as a broken batch, not as data", async () => {
  const stub = stubFetch((body) => {
    const batch = Array.isArray(body) ? body : [body];
    // Answer only the first id: a truncated batch must not be trusted.
    return { json: [{ jsonrpc: "2.0", id: (batch[0] as { id: number }).id, result: "0x" }] };
  });
  try {
    const out = await executeEthCallBatch(ADDRESS, [{ id: 1, calldata: "0x06fdde03" }, { id: 2, calldata: "0x95d89b41" }], "ethereum");
    assert.equal(out, null, "null forces the per-call fallback");
  } finally {
    stub.restore();
  }
});

test("a single call is not wrapped in a batch", async () => {
  const stub = stubFetch(() => ({ json: { jsonrpc: "2.0", id: 1, result: "0x" } }));
  try {
    await executeEthCallBatch(ADDRESS, [{ id: 1, calldata: "0x06fdde03" }], "ethereum");
    assert.ok(!Array.isArray(stub.requests[0]), "one call goes as a plain request");
  } finally {
    stub.restore();
  }
});

test("an empty call list costs nothing", async () => {
  const stub = stubFetch(() => ({ json: [] }));
  try {
    const out = await executeEthCallBatch(ADDRESS, [], "ethereum");
    assert.equal(out?.size, 0);
    assert.equal(stub.requests.length, 0);
  } finally {
    stub.restore();
  }
});
