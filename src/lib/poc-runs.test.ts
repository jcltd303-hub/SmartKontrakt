// src/lib/poc-runs.test.ts
// Task 2 tests: savePocRun sends the full result once, retries send the
// identical body (same UUID), privileged keys and invalid data are
// rejected, and server errors surface with the HTTP status.
// globalThis.fetch is mocked; no network, no real Supabase.

import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { savePocRun, validatePocRunResult, type PocRunResult, type PocRunSupabaseConfig } from "./poc-runs.ts";

const VALID_ID = "123e4567-e89b-42d3-a456-426614174000";

function validResult(overrides: Partial<PocRunResult> = {}): PocRunResult {
  return {
    id: VALID_ID,
    source: "contract Test { function test_x() public {} }",
    status: "passed",
    startedAt: "2026-10-17T20:00:00.000Z",
    finishedAt: "2026-10-17T20:00:01.250Z",
    durationMs: 1250,
    chainId: 1,
    exitCode: 0,
    output: "Ran 1 test: test_x [PASS]",
    truncated: false,
    ...overrides,
  };
}

function jwtWithRole(role: string): string {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "none", typ: "JWT" })}.${b64({ role })}.sig`;
}

function validConfig(overrides: Partial<PocRunSupabaseConfig> = {}): PocRunSupabaseConfig {
  return {
    url: "https://example.supabase.co",
    anonKey: jwtWithRole("anon"),
    enabled: true,
    ...overrides,
  };
}

type CapturedCall = { url: string; init: RequestInit & { headers: Record<string, string> } };
let calls: CapturedCall[];
let statusQueue: number[];

beforeEach(() => {
  calls = [];
  statusQueue = [];
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    calls.push({ url, init: init as CapturedCall["init"] });
    const status = statusQueue.shift() ?? 200;
    return { ok: status >= 200 && status < 300, status };
  }) as typeof fetch;
});

describe("savePocRun request shape", () => {
  it("sends one plain POST (no on_conflict) with the full result row", async () => {
    const result = validResult();
    await savePocRun(result, validConfig());
    assert.equal(calls.length, 1);
    const { url, init } = calls[0];
    // Plain INSERT: ON CONFLICT is incompatible with insert-only RLS
    // (it needs a SELECT grant + SELECT policy), so retries rely on
    // the 409 duplicate-key response instead (see retry test).
    assert.equal(url, "https://example.supabase.co/rest/v1/poc_runs");
    assert.doesNotMatch(url, /on_conflict/);
    assert.equal(init.method, "POST");
    assert.equal(init.headers.Prefer, "return=minimal");
    const body = JSON.parse(init.body as string);
    assert.ok(Array.isArray(body) && body.length === 1);
    assert.deepEqual(body[0], {
      id: VALID_ID,
      source: result.source,
      status: "passed",
      started_at: "2026-10-17T20:00:00.000Z",
      finished_at: "2026-10-17T20:00:01.250Z",
      duration_ms: 1250,
      chain_id: 1,
      exit_code: 0,
      output: "Ran 1 test: test_x [PASS]",
      truncated: false,
    });
  });

  it("retry sends the identical body twice; a 409 duplicate key resolves as already-saved", async () => {
    const result = validResult();
    const config = validConfig();
    statusQueue = [201, 409];
    await savePocRun(result, config);
    await savePocRun(result, config); // 409 -> already saved, not an error
    assert.equal(calls.length, 2);
    assert.equal(calls[0].url, calls[1].url);
    assert.equal(calls[0].init.body, calls[1].init.body);
    assert.deepEqual(JSON.parse(calls[1].init.body as string), JSON.parse(calls[0].init.body as string));
  });

  it("accepts a timed_out result with a null exit code", async () => {
    await savePocRun(validResult({ status: "timed_out", exitCode: null }), validConfig());
    const body = JSON.parse(calls[0].init.body as string);
    assert.equal(body[0].status, "timed_out");
    assert.equal(body[0].exit_code, null);
  });

  it("sends apikey + Authorization for a legacy anon JWT, apikey only for sb_publishable_", async () => {
    await savePocRun(validResult(), validConfig());
    assert.equal(calls[0].init.headers.apikey, jwtWithRole("anon"));
    assert.ok(calls[0].init.headers.Authorization?.startsWith("Bearer "));
    calls = [];
    await savePocRun(validResult(), validConfig({ anonKey: "sb_publishable_testkey123" }));
    assert.equal(calls[0].init.headers.apikey, "sb_publishable_testkey123");
    assert.equal(calls[0].init.headers.Authorization, undefined);
  });
});

describe("savePocRun key rejection", () => {
  it("rejects sb_secret_ keys", async () => {
    await assert.rejects(savePocRun(validResult(), validConfig({ anonKey: "sb_secret_abcdef" })), /publishable or anon/);
    assert.equal(calls.length, 0);
  });

  it("rejects a JWT with role service_role", async () => {
    await assert.rejects(savePocRun(validResult(), validConfig({ anonKey: jwtWithRole("service_role") })), /publishable or anon/);
    assert.equal(calls.length, 0);
  });

  it("accepts sb_publishable_ and legacy anon JWT keys", async () => {
    await savePocRun(validResult(), validConfig({ anonKey: "sb_publishable_testkey123" }));
    await savePocRun(validResult(), validConfig({ anonKey: jwtWithRole("anon") }));
    assert.equal(calls.length, 2);
  });
});

describe("savePocRun validation", () => {
  it("rejects a bad UUID", async () => {
    await assert.rejects(savePocRun(validResult({ id: "not-a-uuid" }), validConfig()), /UUID/);
  });

  it("rejects a bad status", async () => {
    await assert.rejects(
      savePocRun(validResult({ status: "ok" as PocRunResult["status"] }), validConfig()),
      // "unadapted" joined the vocabulary with the TODO pre-check
      // (poc-outcome.ts): an unadapted template scaffold is a saved
      // outcome kind, distinct from a verdict and from an error.
      /passed, failed, error, timed_out, skipped, no_tests, unadapted/,
    );
  });

  it("accepts the unadapted status", async () => {
    await savePocRun(validResult({ status: "unadapted" }), validConfig());
    assert.equal(calls.length, 1);
  });

  it("rejects oversize source and oversize output without truncating", async () => {
    await assert.rejects(savePocRun(validResult({ source: "x".repeat(120_001) }), validConfig()), /source exceeds/);
    await assert.rejects(savePocRun(validResult({ output: "x".repeat(1_000_001) }), validConfig()), /output exceeds/);
    assert.equal(calls.length, 0);
  });

  it("rejects finishedAt before startedAt", async () => {
    await assert.rejects(
      savePocRun(validResult({ startedAt: "2026-10-17T20:00:01.000Z", finishedAt: "2026-10-17T20:00:00.000Z" }), validConfig()),
      /finishedAt must not be before startedAt/,
    );
  });

  it("rejects a non-https URL", async () => {
    await assert.rejects(savePocRun(validResult(), validConfig({ url: "http://example.supabase.co" })), /https/);
  });

  it("rejects a disabled config with a clear not-configured error", async () => {
    await assert.rejects(savePocRun(validResult(), validConfig({ enabled: false })), /Supabase not configured/);
    assert.equal(calls.length, 0);
  });

  it("validatePocRunResult accepts a valid result and throws on invalid input", () => {
    validatePocRunResult(validResult());
    assert.throws(() => validatePocRunResult(validResult({ durationMs: -1 })), /durationMs/);
    assert.throws(() => validatePocRunResult(validResult({ chainId: 1.5 })), /chainId/);
    assert.throws(() => validatePocRunResult(validResult({ exitCode: 0.5 })), /exitCode/);
  });
});

describe("savePocRun server errors", () => {
  it("surfaces 403 and 500 with the status in the message", async () => {
    statusQueue = [403];
    await assert.rejects(savePocRun(validResult(), validConfig()), /HTTP 403/);
    statusQueue = [500];
    await assert.rejects(savePocRun(validResult(), validConfig()), /HTTP 500/);
  });
});
