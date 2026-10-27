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

async function withServer(
  payload: unknown,
  status: number,
  fn: (url: string) => Promise<void>,
  runStatus: unknown = null,
) {
  const server = http.createServer((req, res) => {
    if (req.url === "/status" && runStatus) {
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(runStatus));
      return;
    }
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

test("no calls with the second pass OFF is 'off', not 'smooth'", async () => {
  // The case that produced a false all-clear in practice: a key is present, the
  // run has finished items, and nothing ever called the model.
  const { verdict: _v, ...counters } = HEALTHY;
  const idle = { ...counters, calls: 0, ok: 0 };
  await withServer(idle, 200, async (url) => {
    const r = await checkLlmHealth({ url });
    assert.equal(r.verdict.state, "off");
    assert.equal(r.verdict.code, 0);
    assert.match(r.verdict.reason, /aiSecondPass is false/);
    assert.match(r.verdict.reason, /aiSecondPass": true/);
  }, { state: "running", completed: 12, total: 100, aiSecondPass: false });
});

test("no calls with the second pass ON and items done is a broken call path", async () => {
  const { verdict: _v, ...counters } = HEALTHY;
  await withServer({ ...counters, calls: 0, ok: 0 }, 200, async (url) => {
    const r = await checkLlmHealth({ url });
    assert.equal(r.verdict.state, "degraded");
    assert.equal(r.verdict.code, 1);
    assert.match(r.verdict.reason, /never made|not being reached/);
  }, { state: "running", completed: 5, total: 100, aiSecondPass: true });
});

test("no calls before any item completes is 'waiting', not healthy", async () => {
  const { verdict: _v, ...counters } = HEALTHY;
  await withServer({ ...counters, calls: 0, ok: 0 }, 200, async (url) => {
    const r = await checkLlmHealth({ url });
    assert.equal(r.verdict.state, "waiting");
    assert.equal(r.verdict.code, 0);
    assert.match(r.verdict.reason, /not completed an item/);
  }, { state: "idle", completed: 0, total: 0, aiSecondPass: true });
});

test("a stale worker verdict cannot override a computed non-smooth one", async () => {
  // An older build reports verdict: smooth for a run whose second pass is off.
  const { verdict: _v, ...counters } = HEALTHY;
  await withServer(
    { ...counters, calls: 0, ok: 0, verdict: { state: "smooth", reason: "no LLM calls yet" } },
    200,
    async (url) => {
      const r = await checkLlmHealth({ url });
      assert.equal(r.verdict.state, "off", "the computed verdict must win here");
    },
    { state: "running", completed: 3, total: 10, aiSecondPass: false },
  );
});

test("the judge mirrors the worker's thresholds", () => {
  assert.equal(judge({ ok: 10, empty: 0, error: 0 }).state, "smooth");
  assert.equal(judge({ ok: 4, empty: 1, error: 1 }).state, "degraded"); // 2/6 = 33%
  assert.equal(judge({ ok: 9, empty: 1, error: 0 }).state, "smooth");   // 10% is tolerated
  assert.equal(judge({ ok: 0, empty: 0, error: 0, unavailable: 3 }).state, "off");
  assert.equal(judge({ ok: 0, empty: 0, error: 0 }).state, "waiting");
  assert.equal(judge({ ok: 0, empty: 0, error: 0 }, { aiSecondPass: false, completed: 4 }).state, "off");
  assert.equal(judge({ ok: 0, empty: 0, error: 0 }, { aiSecondPass: true, completed: 4 }).state, "degraded");
});

test("/status nests the health under `llm`; both shapes are read", async () => {
  await withServer({ llm: { ...HEALTHY, calls: 4, ok: 4 }, verdict: { state: "smooth", reason: "4/4" } }, 200, async (url) => {
    const r = await checkLlmHealth({ url });
    assert.equal(r.health.calls, 4);
    assert.equal(r.verdict.state, "smooth");
  });
});
