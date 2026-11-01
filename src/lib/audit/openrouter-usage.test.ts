import assert from "node:assert/strict";
import test from "node:test";
import { getOpenRouterUsage, parseOpenRouterKeyInfo } from "./openrouter-usage.server.ts";

test("parses a funded key's ledger", () => {
  const info = parseOpenRouterKeyInfo({
    data: {
      label: "smartkontrakt",
      usage: 2.5134,
      usage_daily: 0.25,
      usage_weekly: 1.1,
      usage_monthly: 2.4,
      limit: 10,
      limit_remaining: 7.4866,
      is_free_tier: false,
      rate_limit: { requests: 60, interval: "1m" },
    },
  });
  assert.equal(info.label, "smartkontrakt");
  assert.equal(info.usage, 2.5134);
  assert.equal(info.usageDaily, 0.25);
  assert.equal(info.limit, 10);
  assert.equal(info.limitRemaining, 7.4866);
  assert.equal(info.isFreeTier, false);
  assert.equal(info.rateLimitRequests, 60);
  assert.equal(info.rateLimitInterval, "1m");
});

test("parses a pure free-tier key (null limit, no rate_limit block)", () => {
  const info = parseOpenRouterKeyInfo({
    data: { usage: 0, usage_daily: 0, usage_weekly: 0, usage_monthly: 0, limit: null, limit_remaining: null, is_free_tier: true },
  });
  assert.equal(info.limit, null);
  assert.equal(info.limitRemaining, null);
  assert.equal(info.isFreeTier, true);
  assert.equal(info.rateLimitRequests, null);
});

test("malformed payloads parse to nulls, never throw", () => {
  for (const bad of [null, undefined, 42, "nope", {}, { data: null }, { data: { usage: "x" } }]) {
    const info = parseOpenRouterKeyInfo(bad);
    assert.equal(info.usage, null);
    assert.equal(info.isFreeTier, null);
  }
});

type StubCall = { url: string; init?: RequestInit };

function stubFetch(handler: (url: string) => { status: number; body: unknown }): {
  impl: typeof fetch;
  calls: StubCall[];
} {
  const calls: StubCall[] = [];
  const impl = (async (url: unknown, init?: RequestInit) => {
    const u = String(url);
    calls.push({ url: u, init });
    const { status, body } = handler(u);
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
    } as Response;
  }) as typeof fetch;
  return { impl, calls };
}

const KEY_ENV = { OPENROUTER_API_KEY: "sk-or-test-key" } as NodeJS.ProcessEnv;

test("no key configured: configured=false and no HTTP happens", async () => {
  const { impl, calls } = stubFetch(() => ({ status: 200, body: {} }));
  const usage = await getOpenRouterUsage({} as NodeJS.ProcessEnv, impl);
  assert.equal(usage.configured, false);
  assert.equal(usage.probe.ok, false);
  assert.equal(calls.length, 0);
});

test("placeholder key counts as not configured", async () => {
  const { impl, calls } = stubFetch(() => ({ status: 200, body: {} }));
  const usage = await getOpenRouterUsage(
    { OPENROUTER_API_KEY: "MY_OPENROUTER_API_KEY" } as NodeJS.ProcessEnv,
    impl,
  );
  assert.equal(usage.configured, false);
  assert.equal(calls.length, 0);
});

test("key ledger + probe success", async () => {
  const { impl, calls } = stubFetch((url) =>
    url.endsWith("/auth/key")
      ? { status: 200, body: { data: { usage: 1.5, limit: 10, limit_remaining: 8.5, is_free_tier: false } } }
      : { status: 200, body: { choices: [{ message: { content: "ok" } }] } },
  );
  const usage = await getOpenRouterUsage(KEY_ENV, impl);
  assert.equal(usage.configured, true);
  assert.equal(usage.key?.limitRemaining, 8.5);
  assert.equal(usage.keyError, null);
  assert.equal(usage.probe.ok, true);
  assert.ok(usage.probe.latencyMs !== null && usage.probe.latencyMs >= 0);
  assert.equal(calls.length, 2);
  // The key travels only in the Authorization header, never in a URL.
  for (const c of calls) assert.ok(!c.url.includes("sk-or-test-key"));
});

test("probe failure is reported, ledger still returns", async () => {
  const { impl } = stubFetch((url) =>
    url.endsWith("/auth/key")
      ? { status: 200, body: { data: { usage: 0, is_free_tier: true } } }
      : { status: 429, body: { error: { message: "rate-limited" } } },
  );
  const usage = await getOpenRouterUsage(KEY_ENV, impl);
  assert.equal(usage.key?.isFreeTier, true);
  assert.equal(usage.probe.ok, false);
  assert.match(usage.probe.error ?? "", /429/);
  assert.match(usage.probe.error ?? "", /rate-limited/);
});

test("key endpoint failure is reported, probe still runs", async () => {
  const { impl } = stubFetch((url) =>
    url.endsWith("/auth/key")
      ? { status: 401, body: {} }
      : { status: 200, body: { choices: [{ message: { content: "ok" } }] } },
  );
  const usage = await getOpenRouterUsage(KEY_ENV, impl);
  assert.equal(usage.key, null);
  assert.match(usage.keyError ?? "", /401/);
  assert.equal(usage.probe.ok, true);
});
