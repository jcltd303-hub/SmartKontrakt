import test from "node:test";
import assert from "node:assert/strict";
import {
  buildAiReviewPrompt,
  extractJsonContent,
  generateAiSecurityReview,
  parseReviewReply,
  ReviewReplyError,
  resolveOpenRouterConfig,
  resolveOpenRouterModel,
  resolveOpenRouterTimeoutMs,
  isOpenRouterTimeoutError,
  DEFAULT_OPENROUTER_TIMEOUT_MS,
  OPENROUTER_MODELS,
  OPENROUTER_FALLBACK_MODELS,
  DEFAULT_OPENROUTER_MODEL,
  isModelUnavailable,
  modelCandidates,
} from "./ai-review.server.ts";

test("resolveOpenRouterConfig defaults the model and requires a real key", () => {
  assert.equal(resolveOpenRouterConfig({}).apiKey, undefined);
  assert.equal(resolveOpenRouterConfig({}).model, DEFAULT_OPENROUTER_MODEL);
  assert.equal(
    resolveOpenRouterConfig({ OPENROUTER_API_KEY: "MY_OPENROUTER_API_KEY" }).apiKey,
    undefined,
  );
  assert.deepEqual(
    resolveOpenRouterConfig({
      OPENROUTER_API_KEY: "  sk-or-test  ",
      OPENROUTER_MODEL: "anthropic/claude-3.5-sonnet",
    }),
    { apiKey: "sk-or-test", model: "anthropic/claude-3.5-sonnet" },
  );
});

test("resolveOpenRouterModel picks the per-purpose free model, overridable by env", () => {
  // No overrides → the per-purpose free-tier default.
  assert.equal(resolveOpenRouterModel("review", {}), OPENROUTER_MODELS.review);
  assert.equal(resolveOpenRouterModel("code", {}), OPENROUTER_MODELS.code);
  assert.equal(resolveOpenRouterModel("json", {}), OPENROUTER_MODELS.json);
  // Per-purpose override wins over the default but not the global override.
  assert.equal(
    resolveOpenRouterModel("code", { OPENROUTER_MODEL_CODE: "poolside/laguna-s-2.1:free" }),
    "poolside/laguna-s-2.1:free",
  );
  assert.equal(
    resolveOpenRouterModel("code", {
      OPENROUTER_MODEL: "openrouter/free",
      OPENROUTER_MODEL_CODE: "poolside/laguna-s-2.1:free",
    }),
    "openrouter/free",
  );
});

test("extractJsonContent parses raw JSON", () => {
  assert.deepEqual(
    extractJsonContent('{"threatModelReport":"x","foundryTestCode":"y"}'),
    { threatModelReport: "x", foundryTestCode: "y" },
  );
});

test("extractJsonContent unwraps fenced JSON and surrounding prose", () => {
  assert.deepEqual(
    extractJsonContent(
      'Here is the review:\n```json\n{"threatModelReport":"x","foundryTestCode":"y"}\n```\nDone.',
    ),
    { threatModelReport: "x", foundryTestCode: "y" },
  );
  assert.deepEqual(
    extractJsonContent('prefix {"a":1} suffix'),
    { a: 1 },
  );
});

test("extractJsonContent throws when there is no JSON object", () => {
  assert.throws(() => extractJsonContent("no json here"), /JSON object/);
});

// --- tolerant extraction (2026-10-25): free-tier models wrap the
// payload in prose/fences despite response_format, and the old
// first-fence + first-{ to last-} slice died on all of these ---

test("extractJsonContent skips a balanced non-JSON span in the prose", () => {
  // A Solidity sketch in the explanation is a balanced {...} span that
  // is not JSON — it must be skipped, not merged into the payload.
  assert.deepEqual(
    extractJsonContent(
      'The fix looks like: function f() { require(x); } — result: {"hypotheses": [], "stopReason": "none"} (end)',
    ),
    { hypotheses: [], stopReason: "none" },
  );
});

test("extractJsonContent is not corrupted by a brace in trailing prose", () => {
  // The old greedy slice ran to the LAST } in the reply, swallowing
  // the trailing note into the candidate and failing the parse.
  assert.deepEqual(
    extractJsonContent('{"a": {"b": 1}}\nHope that helps }'),
    { a: { b: 1 } },
  );
});

test("extractJsonContent respects braces inside JSON string values", () => {
  // A PoC payload is full of braces inside its code string; they must
  // not open/close spans or truncate the object.
  const payload = {
    foundryTestCode:
      "contract PoC is Test { function test_x() public { uint256 a = 1; if (a > 0) { a += 1; } } }",
    n: 1,
  };
  assert.deepEqual(
    extractJsonContent(`Here is the PoC:\n${JSON.stringify(payload)}\nDone.`),
    payload,
  );
});

test("extractJsonContent tries later fences when the first is not JSON", () => {
  assert.deepEqual(
    extractJsonContent("Sketch:\n```\nnotes, no json\n```\n```json\n{\"a\": 2}\n```"),
    { a: 2 },
  );
});

test("extractJsonContent throws on a truncated reply (no balanced object)", () => {
  // The outer object never closes — mining its first inner object
  // would hand the caller a hypothesis where the envelope belongs.
  assert.throws(
    () => extractJsonContent('{"hypotheses": [{"title": "x", "foundryTestCode": "contract PoC is Test {'),
    /did not contain a JSON object/,
  );
});

test("extractJsonContent's failure names the offending reply (snippet)", () => {
  let message = "";
  try {
    extractJsonContent("Sorry — I cannot produce that analysis in this format.");
  } catch (err) {
    message = err instanceof Error ? err.message : String(err);
  }
  assert.match(message, /did not contain a JSON object/);
  assert.match(message, /Sorry — I cannot produce that analysis/);
});


// --- model gating must degrade, not fail the step ---

test("no configured model is one that a plain API call cannot use", () => {
  // `thinkingmachines/inkling-small:free` was the "code" default and OpenRouter
  // refuses it outside an agentic harness, so every SmartPoC repair failed.
  for (const [purpose, model] of Object.entries(OPENROUTER_MODELS)) {
    assert.doesNotMatch(
      model,
      /inkling/i,
      `the ${purpose} model must not be harness-gated: ${model}`,
    );
  }
});

test("modelCandidates puts the preferred model first and the router last", () => {
  const candidates = modelCandidates("code", {});
  assert.equal(candidates[0], OPENROUTER_MODELS.code);
  assert.equal(candidates.at(-1), "openrouter/free");
  assert.ok(OPENROUTER_FALLBACK_MODELS.includes("openrouter/free"));
  // An explicit override still leads, and the fallback is still available.
  const overridden = modelCandidates("code", { OPENROUTER_MODEL_CODE: "vendor/model:free" });
  assert.equal(overridden[0], "vendor/model:free");
  assert.equal(overridden.at(-1), "openrouter/free");
});

test("modelCandidates de-duplicates when the preferred model is the fallback", () => {
  assert.deepEqual(modelCandidates("code", { OPENROUTER_MODEL: "openrouter/free" }), ["openrouter/free"]);
});

test("a harness-gated 403 is recognised as model-unavailable", () => {
  // The exact body OpenRouter returned, which stopped a SmartPoC repair.
  const gated =
    '{"error":{"message":"thinkingmachines/inkling-small:free is only available on agentic harnesses. Try plugging it into a coding agent or productivity app listed on https://openrouter.ai/apps","code":403,"metadata":{"routing_funnel":[{"step":"Initial Endpoints","endpoint_count":1}],"failed_routing_step":"Gate Free Endpoints by Agentic Harness"}}}';
  assert.equal(isModelUnavailable(403, gated), true);
});

test("failures that are NOT about the model are left to the caller", () => {
  // Falling back on these would just triple the latency.
  assert.equal(isModelUnavailable(403, '{"error":{"message":"Invalid API key"}}'), false);
  assert.equal(isModelUnavailable(500, "upstream provider error"), false);
  assert.equal(isModelUnavailable(429, "rate limit exceeded"), false);
  // A missing model is worth another model, though.
  assert.equal(isModelUnavailable(404, "No endpoints found for the model"), true);
});

// Prompt-path pins from the full detector audit (2026-10-24): a finding's
// SmartBugs label in buildAiReviewPrompt comes from
// smartbugsCategoryForDetector, and three detectors carried labels that
// contradicted their own mechanisms (and their templates' index labels),
// so the model was told the wrong vulnerability class while being handed
// the right template. Before: token-drain -> unchecked_low_level_calls,
// msg-value-loop -> denial_of_service, shadowing -> access_control.
// --- review timeout discipline (2026-10-25): the review call sat
// at 60s under withRetry's default predicate, so a slow free-lane
// generation burned 4 attempts x 60s (each restarting from zero) and
// still fell back to the template — Jer's live worker run showed the
// bare "aborted due to timeout" line for entry after entry. Now: a
// real budget (OPENROUTER_TIMEOUT_MS, default 300s), timeouts fail
// the attempt fast, exactly one counted retry, and a fallback line
// that names model + budget + retry state ---

test("resolveOpenRouterTimeoutMs: env wins, garbage and non-positives fall back to the default", () => {
  assert.equal(DEFAULT_OPENROUTER_TIMEOUT_MS, 300_000);
  assert.equal(resolveOpenRouterTimeoutMs({}), DEFAULT_OPENROUTER_TIMEOUT_MS);
  assert.equal(resolveOpenRouterTimeoutMs({ OPENROUTER_TIMEOUT_MS: "9000" }), 9000);
  assert.equal(resolveOpenRouterTimeoutMs({ OPENROUTER_TIMEOUT_MS: "abc" }), DEFAULT_OPENROUTER_TIMEOUT_MS);
  assert.equal(resolveOpenRouterTimeoutMs({ OPENROUTER_TIMEOUT_MS: "0" }), DEFAULT_OPENROUTER_TIMEOUT_MS);
  assert.equal(resolveOpenRouterTimeoutMs({ OPENROUTER_TIMEOUT_MS: "-5" }), DEFAULT_OPENROUTER_TIMEOUT_MS);
});

test("isOpenRouterTimeoutError recognises the AbortSignal.timeout shape from the worker log", () => {
  assert.equal(
    isOpenRouterTimeoutError(new DOMException("The operation was aborted due to timeout", "TimeoutError")),
    true,
  );
  assert.equal(isOpenRouterTimeoutError(new DOMException("The user aborted a request", "AbortError")), true);
  assert.equal(isOpenRouterTimeoutError(new Error("OpenRouter returned HTTP 500: upstream")), false);
  assert.equal(isOpenRouterTimeoutError("timeout"), false);
});

const REVIEW_OK = JSON.stringify({
  choices: [
    {
      message: {
        content: JSON.stringify({
          threatModelReport: "tm",
          foundryTestCode: "contract PoC is Test {}",
          economicRiskSummary: "eco",
        }),
      },
    },
  ],
});

function captureWarn(): { lines: string[]; restore: () => void } {
  const lines: string[] = [];
  const orig = console.warn;
  console.warn = (...args: unknown[]) => {
    lines.push(args.map((a) => String(a)).join(" "));
  };
  return { lines, restore: () => { console.warn = orig; } };
}

async function withFetchAndEnv(
  fetchImpl: (call: number) => Promise<Response>,
  fn: (calls: () => number) => Promise<void>,
): Promise<void> {
  const origFetch = globalThis.fetch;
  const savedEnv = {
    OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY,
    OPENROUTER_MODEL: process.env.OPENROUTER_MODEL,
    OPENROUTER_TIMEOUT_MS: process.env.OPENROUTER_TIMEOUT_MS,
  };
  let calls = 0;
  globalThis.fetch = (() => fetchImpl(++calls)) as typeof fetch;
  process.env.OPENROUTER_API_KEY = "sk-test";
  process.env.OPENROUTER_MODEL = "test/model";
  process.env.OPENROUTER_TIMEOUT_MS = "9000";
  try {
    await fn(() => calls);
  } finally {
    globalThis.fetch = origFetch;
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test("generateAiSecurityReview retries ONCE on a timeout and returns the LLM review", async () => {
  const warn = captureWarn();
  try {
    await withFetchAndEnv(
      async (call) => {
        if (call === 1) {
          throw new DOMException("The operation was aborted due to timeout", "TimeoutError");
        }
        return new Response(REVIEW_OK, { status: 200, headers: { "Content-Type": "application/json" } });
      },
      async (calls) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "openrouter");
        assert.equal(review.threatModelReport, "tm");
        // Exactly two fetches: the timed-out attempt + the one retry.
        // (Under the old predicate withRetry alone would have made 4.)
        assert.equal(calls(), 2);
      },
    );
  } finally {
    warn.restore();
  }
  assert.ok(
    warn.lines.some((l) => /timed out \(model test\/model, timeout 9000ms\) — retrying once/.test(l)),
    `retry must be logged with model + budget, got: ${warn.lines.join(" | ")}`,
  );
});

test("generateAiSecurityReview falls back after the retry also times out — log names model, budget, retry", async () => {
  const warn = captureWarn();
  try {
    await withFetchAndEnv(
      async () => {
        throw new DOMException("The operation was aborted due to timeout", "TimeoutError");
      },
      async (calls) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "template");
        assert.equal(calls(), 2);
      },
    );
  } finally {
    warn.restore();
  }
  const fallback = warn.lines.find((l) => l.includes("falling back to structured template"));
  assert.ok(fallback, `expected a fallback line, got: ${warn.lines.join(" | ")}`);
  assert.match(fallback!, /model test\/model/);
  assert.match(fallback!, /timeout 9000ms/);
  assert.match(fallback!, /timeout retry attempted and exhausted/);
  assert.match(fallback!, /TimeoutError/);
});

test("generateAiSecurityReview does NOT retry a non-timeout failure", async () => {
  const warn = captureWarn();
  try {
    await withFetchAndEnv(
      async () =>
        new Response('{"error":{"message":"malformed request"}}', {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }),
      async (calls) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "template");
        // One fetch, straight to the fallback — today's behavior for
        // non-timeout errors is unchanged.
        assert.equal(calls(), 1);
      },
    );
  } finally {
    warn.restore();
  }
  const fallback = warn.lines.find((l) => l.includes("falling back to structured template"));
  assert.ok(fallback);
  assert.doesNotMatch(fallback!, /timeout retry attempted/);
});

// --- review reply-shape discipline (2026-10-25): the timeout fix
// above was not the end of it. In the same 59,852-address run the
// review call started RETURNING in time — and validation rejected
// the shape: "OpenRouter reply was missing threatModelReport /
// foundryTestCode", straight to the template, with no record of
// what the reply contained (keys renamed? wrapped? cut at the token
// budget? an empty code field?). Now: the error carries the missing
// fields, the received top-level keys and the truncation signal
// (finish_reason rides in the same response body — it was always
// reachable, just never read), and the reply gets ONE corrective
// retry naming the exact fields before the template fallback ---

function replyEnvelope(content: string, finishReason?: string): string {
  return JSON.stringify({
    choices: [
      {
        message: { content },
        ...(finishReason ? { finish_reason: finishReason } : {}),
      },
    ],
  });
}

const COMPLETE_REPLY = JSON.stringify({
  threatModelReport: "tm",
  foundryTestCode: "contract PoC is Test {}",
  economicRiskSummary: "eco",
});

/** withFetchAndEnv, but the mock sees each request body (the
 *  corrective instruction is asserted on the actual wire text). */
async function withFetchBodies(
  fetchImpl: (call: number) => Promise<Response>,
  fn: (calls: () => number, bodies: string[]) => Promise<void>,
): Promise<void> {
  const origFetch = globalThis.fetch;
  const savedEnv = {
    OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY,
    OPENROUTER_MODEL: process.env.OPENROUTER_MODEL,
    OPENROUTER_TIMEOUT_MS: process.env.OPENROUTER_TIMEOUT_MS,
  };
  let calls = 0;
  const bodies: string[] = [];
  globalThis.fetch = ((_url: unknown, init?: { body?: unknown }) => {
    bodies.push(typeof init?.body === "string" ? init.body : "");
    return fetchImpl(++calls);
  }) as typeof fetch;
  process.env.OPENROUTER_API_KEY = "sk-test";
  process.env.OPENROUTER_MODEL = "test/model";
  process.env.OPENROUTER_TIMEOUT_MS = "9000";
  try {
    await fn(() => calls, bodies);
  } finally {
    globalThis.fetch = origFetch;
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

function ok200(body: string): Response {
  return new Response(body, { status: 200, headers: { "Content-Type": "application/json" } });
}

test("parseReviewReply: a complete object passes; a missing field throws the diagnosis", () => {
  const ok = parseReviewReply(COMPLETE_REPLY, "stop");
  assert.equal(ok.source, "openrouter");
  assert.equal(ok.threatModelReport, "tm");
  assert.throws(
    () =>
      parseReviewReply(
        JSON.stringify({ threatModelReport: "tm", economicRiskSummary: "eco" }),
        "stop",
      ),
    (err: unknown) => {
      assert.ok(err instanceof ReviewReplyError);
      assert.deepEqual(err.missingFields, ["foundryTestCode"]);
      assert.deepEqual(err.receivedKeys, ["threatModelReport", "economicRiskSummary"]);
      assert.equal(err.truncated, false);
      assert.match(err.message, /missing foundryTestCode/);
      assert.match(err.message, /reply keys: threatModelReport, economicRiskSummary/);
      return true;
    },
  );
  // A non-object JSON reply (array wrap) is the same failure class,
  // named as such — never a bare "missing fields".
  assert.throws(
    () => parseReviewReply(JSON.stringify([{ threatModelReport: "tm" }]), "stop"),
    (err: unknown) => {
      assert.ok(err instanceof ReviewReplyError);
      assert.match(err.message, /JSON array, not an object/);
      assert.deepEqual(err.missingFields, ["threatModelReport", "foundryTestCode"]);
      return true;
    },
  );
});

test("generateAiSecurityReview: a complete reply takes exactly one call, no corrective retry", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
      async () => ok200(replyEnvelope(COMPLETE_REPLY, "stop")),
      async (calls) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "openrouter");
        assert.equal(review.foundryTestCode, "contract PoC is Test {}");
        assert.equal(calls(), 1);
      },
    );
  } finally {
    warn.restore();
  }
  assert.ok(
    !warn.lines.some((l) => l.includes("reply unusable")),
    `no corrective retry may fire on a complete reply, got: ${warn.lines.join(" | ")}`,
  );
});

test("generateAiSecurityReview: missing-fields reply gets ONE corrective retry naming the exact fields", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
      async (call) =>
        call === 1
          ? ok200(
              replyEnvelope(
                JSON.stringify({ threatModelReport: "tm", economicRiskSummary: "eco" }),
                "stop",
              ),
            )
          : ok200(replyEnvelope(COMPLETE_REPLY, "stop")),
      async (calls, bodies) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "openrouter");
        assert.equal(review.foundryTestCode, "contract PoC is Test {}");
        assert.equal(calls(), 2);
        // The corrective instruction rides in the second request's
        // messages and names the missing field + the exact schema
        // keys. (Asserted on the DECODED body — on the wire the
        // quotes are JSON-escaped.)
        const second = JSON.parse(bodies[1]!) as { messages: Array<{ content: string }> };
        const corrective = second.messages[second.messages.length - 1]!.content;
        assert.match(corrective, /missing "foundryTestCode"/);
        assert.match(
          corrective,
          /exactly these keys: "threatModelReport", "foundryTestCode", "economicRiskSummary"/,
        );
        assert.match(corrective, /ONLY the complete JSON object/);
        // The first request carries no corrective message at all.
        const first = JSON.parse(bodies[0]!) as { messages: Array<{ content: string }> };
        assert.equal(first.messages.length, 2);
      },
    );
  } finally {
    warn.restore();
  }
  const retryLine = warn.lines.find((l) => l.includes("reply unusable"));
  assert.ok(retryLine, `expected the corrective-retry line, got: ${warn.lines.join(" | ")}`);
  assert.match(retryLine!, /missing foundryTestCode/);
  assert.match(retryLine!, /reply keys: threatModelReport, economicRiskSummary/);
});

test("generateAiSecurityReview: missing fields twice falls back — the log names the keys the reply DID contain", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
      async () => ok200(replyEnvelope(JSON.stringify({ summary: "not a review" }), "stop")),
      async (calls) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "template");
        assert.equal(calls(), 2);
      },
    );
  } finally {
    warn.restore();
  }
  const fallback = warn.lines.find((l) => l.includes("falling back to structured template"));
  assert.ok(fallback, `expected a fallback line, got: ${warn.lines.join(" | ")}`);
  assert.match(fallback!, /missing threatModelReport \/ foundryTestCode/);
  assert.match(fallback!, /reply keys: summary/);
  assert.match(fallback!, /corrective retry attempted and exhausted/);
});

test("generateAiSecurityReview: a finish_reason=length reply is named as truncation and the retry demands compact code", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
      async (call) =>
        call === 1
          ? ok200(
              replyEnvelope(
                JSON.stringify({ threatModelReport: "tm", economicRiskSummary: "eco" }),
                "length",
              ),
            )
          : ok200(replyEnvelope(COMPLETE_REPLY, "stop")),
      async (calls, bodies) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "openrouter");
        assert.equal(calls(), 2);
        // The corrective instruction for a truncated reply also tells
        // the model WHY compactness matters (same-size resend = cut again).
        const second = JSON.parse(bodies[1]!) as { messages: Array<{ content: string }> };
        const corrective = second.messages[second.messages.length - 1]!.content;
        assert.match(corrective, /cut off at the token limit/);
        assert.match(corrective, /more compact foundryTestCode/);
      },
    );
  } finally {
    warn.restore();
  }
  const retryLine = warn.lines.find((l) => l.includes("reply unusable"));
  assert.ok(retryLine, `expected the corrective-retry line, got: ${warn.lines.join(" | ")}`);
  assert.match(retryLine!, /truncated at max_tokens 8000/);
  assert.match(retryLine!, /finish_reason "length"/);
});

test("buildAiReviewPrompt labels corrected detectors with their mechanism class and right template", () => {
  const finding = (detector: string, title: string, summary: string) =>
    ({
      id: `audit-${detector}`,
      severity: "high",
      swc: null,
      title,
      confidence: "high",
      detector,
      summary,
      walkthrough: "",
      exploitSolidity: "",
      remediationSolidity: "",
      locationFn: "f",
      locationLine: 1,
      snippet: "",
    }) as Parameters<typeof buildAiReviewPrompt>[2][number];
  const cases = [
    ["token-drain", "SmartBugs: access_control", "46-token-rescue.t.sol"],
    ["msg-value-loop", "SmartBugs: other", "22-msg-value-loop.t.sol"],
    ["shadowing", "SmartBugs: other", "33-shadowing-mismatch.t.sol"],
  ] as const;
  for (const [detector, label, template] of cases) {
    const { user } = buildAiReviewPrompt("Target", "contract Target {}", [
      finding(detector, `${detector} finding`, `${detector} summary`),
    ]);
    assert.ok(user.includes(label), `${detector}: prompt must carry "${label}"`);
    assert.ok(user.includes(`--- Template 1: ${template} ---`), `${detector}: prompt must inject ${template} first`);
  }
});
