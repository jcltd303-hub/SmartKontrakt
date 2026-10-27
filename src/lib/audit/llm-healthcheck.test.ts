import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";

import { checkLlmHealth, judge } from "../../../scripts/llm-healthcheck.mjs";

/**
 * The health check script (2026-10-27).
 *
 * Runs a real HTTP server in-process and points the script at it, so the whole
 * path — request, JSON, verdict, exit code — is exercised rather than a stub.
 */

async function withServer(payload: unknown, status: number, fn: (url: string) => Promise<void>) {
  const server = http.createServer((req, res) => {
    if (req.url !== "/health/llm") {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(payload));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

const HEALTHY = {
  verdict: { state: "smooth", reason: "18/18 usable replies" },
  calls: 18, ok: 18, empty: 0, error: 0, unavailable: 0,
  consecutiveFailures: 0, lastError: null, lastOkAt: "2026-10-27T18:41:02.000Z",
  model: "(default)", keyPresent: true,
};

test("a healthy worker exits 0", async () => {
  await withServer(HEALTHY, 200, async (url) => {
    const r = await checkLlmHealth({ url });
    assert.equal(r.reachable, true);
    assert.equal(r.verdict.state, "smooth");
    assert.equal(r.verdict.code, 0);
    assert.equal(r.keyPresent, true);
  });
});

test("a dead worker exits 2 and the reason carries the last error", async () => {
  // No `verdict` in the payload on purpose: this exercises the script's own
  // judgement from the counters. Test 7 covers the worker-verdict-wins path.
  const { verdict: _drop, ...counters } = HEALTHY;
  await withServer({ ...counters, ok: 2, error: 3, calls: 5, consecutiveFailures: 3, lastError: "502 bad gateway" }, 200, async (url) => {
    const r = await checkLlmHealth({ url });
    assert.equal(r.verdict.state, "dead");
    assert.equal(r.verdict.code, 2);
    assert.match(r.verdict.reason, /502/);
  });
});

test("a run with no key is 'off', not a failure", async () => {
  const { verdict: _drop, ...counters } = HEALTHY;
  await withServer({ ...counters, ok: 0, calls: 5, unavailable: 5, keyPresent: false }, 200, async (url) => {
    const r = await checkLlmHealth({ url });
    assert.equal(r.verdict.state, "off");
    assert.equal(r.verdict.code, 0);
  });
});

test("an HTTP error is unreachable, and says which endpoint", async () => {
  await withServer({ error: "nope" }, 503, async (url) => {
    const r = await checkLlmHealth({ url });
    assert.equal(r.reachable, false);
    assert.equal(r.verdict.code, 2);
    assert.match(r.verdict.reason, /503/);
    assert.match(r.verdict.reason, /\/health\/llm/);
  });
});

test("a closed port is unreachable with a fixable message", async () => {
  const r = await checkLlmHealth({ url: "http://127.0.0.1:9" });
  assert.equal(r.reachable, false);
  assert.equal(r.verdict.code, 2);
  assert.match(r.verdict.reason, /is the worker running/);
});

test("the judge mirrors the worker's thresholds", () => {
  assert.equal(judge({ ok: 10, empty: 0, error: 0 }).state, "smooth");
  assert.equal(judge({ ok: 4, empty: 1, error: 1 }).state, "degraded"); // 2/6 = 33%
  assert.equal(judge({ ok: 9, empty: 1, error: 0 }).state, "smooth");   // 10% is tolerated
  assert.equal(judge({ ok: 0, empty: 0, error: 0, unavailable: 3 }).state, "off");
  assert.equal(judge({ ok: 0, empty: 0, error: 0 }).state, "smooth");
});

test("/status nests the health under `llm`; both shapes are read", async () => {
  await withServer({ llm: { ...HEALTHY, calls: 4, ok: 4 }, verdict: { state: "smooth", reason: "4/4" } }, 200, async (url) => {
    const r = await checkLlmHealth({ url });
    assert.equal(r.health.calls, 4);
    assert.equal(r.verdict.state, "smooth");
  });
});
