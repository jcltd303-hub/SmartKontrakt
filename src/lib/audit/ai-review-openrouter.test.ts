import test from "node:test";
import assert from "node:assert/strict";
import {
  buildAiReviewPrompt,
  buildAiReviewTestPrompt,
  extractJsonContent,
  extractReviewTestCode,
  generateAiSecurityReview,
  parseNarrativeReply,
  parseTestCodeReply,
  ReviewCodeError,
  ReviewReplyError,
  NARRATIVE_MAX_TOKENS,
  CODE_MAX_TOKENS,
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

test("per-purpose defaults are the 2026-10-25 live-catalog picks", () => {
  // Pinned literally on purpose: a free-tier id churns silently, and the
  // suite should go red the day a default changes without the catalog
  // re-check recorded in the OPENROUTER_MODELS header comment. Facts there:
  // Ultra is the strongest free reasoning class (1M ctx, 65,536 max
  // completion, endpoint healthy); Laguna S 2.1 is the free list's dedicated
  // frontier coder (262K ctx, 32,768 max completion); Nemotron 3 Super —
  // the schema-native json candidate — was passed over because its single
  // endpoint was flagged (status -5) while both picked models sat at 0.
  assert.equal(OPENROUTER_MODELS.review, "nvidia/nemotron-3-ultra-550b-a55b:free");
  assert.equal(OPENROUTER_MODELS.code, "poolside/laguna-s-2.1:free");
  assert.equal(OPENROUTER_MODELS.json, "nvidia/nemotron-3-ultra-550b-a55b:free");
  assert.equal(DEFAULT_OPENROUTER_MODEL, OPENROUTER_MODELS.review);
  for (const model of Object.values(OPENROUTER_MODELS)) {
    assert.ok(model.endsWith(":free"), `default must be a free-tier id: ${model}`);
  }
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

function captureWarn(): { lines: string[]; restore: () => void } {
  const lines: string[] = [];
  const orig = console.warn;
  console.warn = (...args: unknown[]) => {
    lines.push(args.map((a) => String(a)).join(" "));
  };
  return { lines, restore: () => { console.warn = orig; } };
}

// --- split review generation (2026-10-25): the review is TWO calls
// now — a narrative JSON call on the "review" purpose and a raw
// test-code call on the "code" purpose — because the single combined
// call kept dying at the token cap (prose threat model as a JSON
// string ate the budget; the test code was never born). The old
// single-call tests were reworked for the split: the same
// disciplines (one timeout retry, no retry on other transport
// errors, one corrective retry per call, template fallback with the
// full diagnosis) are asserted PER CALL, and fetch counts reflect
// two logical calls. ---

const NARRATIVE_REPLY = JSON.stringify({
  threatModelReport: "tm",
  economicRiskSummary: "eco",
});

const TEST_CODE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract PoC is Test {
    function test_primaryFinding() public {
        assertTrue(true);
    }
}`;

const CODE_REPLY = "```solidity\n" + TEST_CODE + "\n```";

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

function ok200(body: string): Response {
  return new Response(body, { status: 200, headers: { "Content-Type": "application/json" } });
}

const NARRATIVE_OK = (): Response => ok200(replyEnvelope(NARRATIVE_REPLY, "stop"));
const CODE_OK = (): Response => ok200(replyEnvelope(CODE_REPLY, "stop"));

/** Body-recording fetch mock: the implementation sees each request
 *  body (corrective instructions are asserted on the actual wire
 *  text). `env` replaces the model-related environment — the
 *  default pins the global override the way the older tests did. */
async function withFetchBodies(
  fetchImpl: (call: number) => Promise<Response>,
  fn: (calls: () => number, bodies: string[]) => Promise<void>,
  env: Record<string, string | undefined> = { OPENROUTER_MODEL: "test/model" },
): Promise<void> {
  const origFetch = globalThis.fetch;
  const KEYS = [
    "OPENROUTER_API_KEY",
    "OPENROUTER_MODEL",
    "OPENROUTER_MODEL_REVIEW",
    "OPENROUTER_MODEL_CODE",
    "OPENROUTER_MODEL_JSON",
    "OPENROUTER_TIMEOUT_MS",
  ] as const;
  const saved = new Map(KEYS.map((k) => [k, process.env[k]]));
  let calls = 0;
  const bodies: string[] = [];
  globalThis.fetch = ((_url: unknown, init?: { body?: unknown }) => {
    bodies.push(typeof init?.body === "string" ? init.body : "");
    return fetchImpl(++calls);
  }) as typeof fetch;
  process.env.OPENROUTER_API_KEY = "sk-test";
  process.env.OPENROUTER_TIMEOUT_MS = "9000";
  for (const k of KEYS) {
    if (k === "OPENROUTER_API_KEY" || k === "OPENROUTER_TIMEOUT_MS") continue;
    const v = env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    await fn(() => calls, bodies);
  } finally {
    globalThis.fetch = origFetch;
    for (const [k, v] of saved) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test("generateAiSecurityReview (split): happy path is two calls — narrative JSON, then raw test code", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
      async (call) => (call === 1 ? NARRATIVE_OK() : CODE_OK()),
      async (calls, bodies) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "openrouter");
        assert.equal(review.threatModelReport, "tm");
        assert.equal(review.economicRiskSummary, "eco");
        // The assembled return shape is the pre-split one, unchanged.
        assert.equal(review.foundryTestCode, TEST_CODE);
        assert.equal(calls(), 2);
        // Call A: JSON mode at the narrative budget.
        const a = JSON.parse(bodies[0]!) as {
          response_format?: unknown;
          max_tokens?: number;
          model?: string;
        };
        assert.deepEqual(a.response_format, { type: "json_object" });
        assert.equal(a.max_tokens, NARRATIVE_MAX_TOKENS);
        assert.equal(a.model, "test/model");
        // Call B: NO response_format (raw code), the code budget,
        // and its prompt carries call A's threat model — the aiming
        // context the single combined call had implicitly.
        const b = JSON.parse(bodies[1]!) as {
          response_format?: unknown;
          max_tokens?: number;
          messages: Array<{ content: string }>;
        };
        assert.equal(b.response_format, undefined);
        assert.equal(b.max_tokens, CODE_MAX_TOKENS);
        const bUser = b.messages[1]!.content;
        assert.match(bUser, /THREAT MODEL \(produced by the narrative pass/);
        assert.ok(bUser.includes("\ntm"), "call B must carry call A's threat model");
      },
    );
  } finally {
    warn.restore();
  }
  assert.ok(
    !warn.lines.some((l) => l.includes("reply unusable") || l.includes("retrying once")),
    `no retries on the happy path, got: ${warn.lines.join(" | ")}`,
  );
});

test("generateAiSecurityReview (split): call A resolves the review purpose, call B the code purpose", async () => {
  await withFetchBodies(
    async (call) => (call === 1 ? NARRATIVE_OK() : CODE_OK()),
    async (calls, bodies) => {
      const review = await generateAiSecurityReview("Target", "contract Target {}", []);
      assert.equal(review.source, "openrouter");
      assert.equal(calls(), 2);
      const a = JSON.parse(bodies[0]!) as { model?: string };
      const b = JSON.parse(bodies[1]!) as { model?: string };
      assert.equal(a.model, OPENROUTER_MODELS.review);
      assert.equal(b.model, "test/code-model");
    },
    { OPENROUTER_MODEL_CODE: "test/code-model" },
  );
});

test("generateAiSecurityReview (split): a timeout on call A retries ONCE, then both calls complete", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
      async (call) => {
        if (call === 1) {
          throw new DOMException("The operation was aborted due to timeout", "TimeoutError");
        }
        return call === 2 ? NARRATIVE_OK() : CODE_OK();
      },
      async (calls) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "openrouter");
        assert.equal(review.threatModelReport, "tm");
        // The timed-out attempt + its one retry + call B. (Under the
        // old withRetry predicate alone this would have been 4+.)
        assert.equal(calls(), 3);
      },
    );
  } finally {
    warn.restore();
  }
  assert.ok(
    warn.lines.some((l) => /narrative call timed out \(model test\/model, timeout 9000ms\) — retrying once/.test(l)),
    `retry must be logged per call with model + budget, got: ${warn.lines.join(" | ")}`,
  );
});

test("generateAiSecurityReview (split): call A timing out twice falls back before call B is ever made", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
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
  assert.match(fallback!, /failed call: narrative/);
  assert.match(fallback!, /model test\/model/);
  assert.match(fallback!, /timeout 9000ms/);
  assert.match(fallback!, /timeout retry attempted and exhausted/);
  assert.match(fallback!, /TimeoutError/);
});

test("generateAiSecurityReview (split): a non-timeout failure on call A is NOT retried", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
      async () =>
        new Response('{"error":{"message":"malformed request"}}', {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }),
      async (calls) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "template");
        // One fetch, straight to the fallback — behavior for
        // non-timeout transport errors is unchanged by the split.
        assert.equal(calls(), 1);
      },
    );
  } finally {
    warn.restore();
  }
  const fallback = warn.lines.find((l) => l.includes("falling back to structured template"));
  assert.ok(fallback);
  assert.doesNotMatch(fallback!, /retry attempted/);
});

// --- per-call reply-shape discipline (2026-10-25) --------------
// The corrective-retry discipline from the single-call review,
// scoped per call in the split: shape failures name what is missing
// (narrative: fields + received keys; test code: the problems),
// exactly ONE corrective retry per call, then today's fallback with
// the full diagnosis and WHICH call failed. An empty completion
// ('returned no message content') also retries once per call —
// Jer's log showed it going straight to the fallback.
// ---------------------------------------------------------------

test("budget pins: each split call carries exactly one artifact", () => {
  assert.equal(NARRATIVE_MAX_TOKENS, 4000);
  assert.equal(CODE_MAX_TOKENS, 16000);
});

test("parseNarrativeReply: a complete object passes; a missing field throws the diagnosis", () => {
  const ok = parseNarrativeReply(NARRATIVE_REPLY, "stop");
  assert.equal(ok.threatModelReport, "tm");
  assert.equal(ok.economicRiskSummary, "eco");
  // economicRiskSummary is defaulted, not required.
  assert.equal(
    parseNarrativeReply(JSON.stringify({ threatModelReport: "tm" }), "stop").economicRiskSummary,
    "Completed OpenRouter threat review.",
  );
  assert.throws(
    () => parseNarrativeReply(JSON.stringify({ economicRiskSummary: "eco" }), "stop"),
    (err: unknown) => {
      assert.ok(err instanceof ReviewReplyError);
      assert.deepEqual(err.missingFields, ["threatModelReport"]);
      assert.deepEqual(err.receivedKeys, ["economicRiskSummary"]);
      assert.equal(err.truncated, false);
      assert.match(err.message, /missing threatModelReport/);
      assert.match(err.message, /reply keys: economicRiskSummary/);
      return true;
    },
  );
  // The model sometimes wraps the object in a one-element array —
  // still a shape failure, with the array called out.
  assert.throws(
    () => parseNarrativeReply(JSON.stringify([{ threatModelReport: "tm" }]), "stop"),
    (err: unknown) => {
      assert.ok(err instanceof ReviewReplyError);
      assert.match(err.message, /JSON array, not an object/);
      assert.deepEqual(err.missingFields, ["threatModelReport"]);
      return true;
    },
  );
  // Truncation is carried with the NARRATIVE budget in the note.
  assert.throws(
    () => parseNarrativeReply(JSON.stringify({ economicRiskSummary: "eco" }), "length"),
    (err: unknown) => {
      assert.ok(err instanceof ReviewReplyError);
      assert.equal(err.truncated, true);
      assert.equal(err.maxTokens, NARRATIVE_MAX_TOKENS);
      assert.match(err.message, /truncated at max_tokens 4000/);
      return true;
    },
  );
});

test("parseTestCodeReply: fenced Test code passes; the Test fence wins over a helper fence", () => {
  assert.equal(parseTestCodeReply(CODE_REPLY, "stop"), TEST_CODE);
  const twoFences =
    "```solidity\ncontract Helper {\n    function poke() public pure returns (uint256) { return 1; }\n}\n```\n\n```solidity\n" +
    TEST_CODE +
    "\n```";
  assert.equal(parseTestCodeReply(twoFences, "stop"), TEST_CODE);
  // Raw unfenced code is accepted too (extractCodeBlock lineage).
  assert.equal(parseTestCodeReply(TEST_CODE, "stop"), TEST_CODE);
  assert.equal(extractReviewTestCode("no fences at all"), "no fences at all");
});

test("parseTestCodeReply: prose and helper-only replies throw ReviewCodeError naming the problems", () => {
  assert.throws(
    () => parseTestCodeReply("no code here", "stop"),
    (err: unknown) => {
      assert.ok(err instanceof ReviewCodeError);
      assert.match(err.message, /test-code reply was unusable/);
      assert.match(err.message, /declares no Test contract/);
      assert.match(err.message, /no executable test function/);
      assert.match(err.correctiveInstruction(), /exactly one ```solidity fenced code block/);
      return true;
    },
  );
  assert.throws(
    () =>
      parseTestCodeReply(
        "```solidity\ncontract Helper {\n    function poke() public pure returns (uint256) { return 1; }\n}\n```",
        "length",
      ),
    (err: unknown) => {
      assert.ok(err instanceof ReviewCodeError);
      assert.equal(err.truncated, true);
      assert.match(err.message, /truncated at max_tokens 16000/);
      assert.match(err.correctiveInstruction(), /more compact test/);
      return true;
    },
  );
});

test("generateAiSecurityReview (split): a narrative reply missing threatModelReport gets ONE corrective retry scoped to call A", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
      async (call) => {
        if (call === 1) {
          return ok200(replyEnvelope(JSON.stringify({ economicRiskSummary: "eco", summary: "x" }), "stop"));
        }
        if (call === 2) return NARRATIVE_OK();
        return CODE_OK();
      },
      async (calls, bodies) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "openrouter");
        assert.equal(calls(), 3);
        // The retry's last user message names the missing field and
        // the exact required keys — asserted on the wire text.
        const second = JSON.parse(bodies[1]!) as { messages: Array<{ content: string }> };
        const corrective = second.messages[second.messages.length - 1]!.content;
        assert.match(corrective, /missing "threatModelReport"/);
        assert.match(corrective, /exactly these keys: "threatModelReport", "economicRiskSummary"/);
        assert.match(corrective, /ONLY the complete JSON object/);
        // The first request carried no corrective message.
        const first = JSON.parse(bodies[0]!) as { messages: unknown[] };
        assert.equal(first.messages.length, 2);
        // Call B ran exactly once, after A completed (bodies[2] is
        // the code call — no response_format).
        const third = JSON.parse(bodies[2]!) as { response_format?: unknown };
        assert.equal(third.response_format, undefined);
      },
    );
  } finally {
    warn.restore();
  }
  const retryLine = warn.lines.find((l) => l.includes("narrative reply unusable"));
  assert.ok(retryLine, `expected a shape-retry line, got: ${warn.lines.join(" | ")}`);
  assert.match(retryLine!, /missing threatModelReport/);
  assert.match(retryLine!, /reply keys: economicRiskSummary, summary/);
  assert.match(retryLine!, /retrying once with a corrective instruction/);
});

test("generateAiSecurityReview (split): narrative shape failure twice falls back — call B never runs, log names the received keys", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
      async () => ok200(replyEnvelope(JSON.stringify({ summary: "not a review" }), "stop")),
      async (calls) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "template");
        // Two narrative attempts, ZERO code calls.
        assert.equal(calls(), 2);
      },
    );
  } finally {
    warn.restore();
  }
  const fallback = warn.lines.find((l) => l.includes("falling back to structured template"));
  assert.ok(fallback, `expected a fallback line, got: ${warn.lines.join(" | ")}`);
  assert.match(fallback!, /failed call: narrative/);
  assert.match(fallback!, /missing threatModelReport/);
  assert.match(fallback!, /reply keys: summary/);
  assert.match(fallback!, /corrective retry attempted and exhausted/);
});

test("generateAiSecurityReview (split): a truncated narrative reply is named as truncation and the retry demands concision", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
      async (call) => {
        if (call === 1) return ok200(replyEnvelope(JSON.stringify({ economicRiskSummary: "eco" }), "length"));
        if (call === 2) return NARRATIVE_OK();
        return CODE_OK();
      },
      async (calls, bodies) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "openrouter");
        assert.equal(calls(), 3);
        const second = JSON.parse(bodies[1]!) as { messages: Array<{ content: string }> };
        const corrective = second.messages[second.messages.length - 1]!.content;
        assert.match(corrective, /cut off at the token limit/);
        assert.match(corrective, /keep the threat model concise/);
      },
    );
  } finally {
    warn.restore();
  }
  const retryLine = warn.lines.find((l) => l.includes("narrative reply unusable"));
  assert.ok(retryLine, `expected a shape-retry line, got: ${warn.lines.join(" | ")}`);
  assert.match(retryLine!, /truncated at max_tokens 4000/);
  assert.match(retryLine!, /finish_reason "length"/);
});

test("generateAiSecurityReview (split): a test-code reply with no fenced Test code gets ONE corrective retry; call A is not re-called", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
      async (call) => {
        if (call === 1) return NARRATIVE_OK();
        if (call === 2) return ok200(replyEnvelope("Here is the test you asked for — it reenters the vault.", "stop"));
        return CODE_OK();
      },
      async (calls, bodies) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "openrouter");
        assert.equal(review.foundryTestCode, TEST_CODE);
        assert.equal(calls(), 3);
        // The corrective demands exactly one fenced block, no JSON.
        const third = JSON.parse(bodies[2]!) as { messages: Array<{ content: string }> };
        const corrective = third.messages[third.messages.length - 1]!.content;
        assert.match(corrective, /exactly one ```solidity fenced code block/);
        assert.match(corrective, /no JSON, no prose/);
        // Exactly ONE request in the whole run carried
        // response_format — call A ran once and was never redone.
        const jsonCalls = bodies.filter(
          (b) => (JSON.parse(b) as { response_format?: unknown }).response_format !== undefined,
        );
        assert.equal(jsonCalls.length, 1);
      },
    );
  } finally {
    warn.restore();
  }
  const retryLine = warn.lines.find((l) => l.includes("test-code reply unusable"));
  assert.ok(retryLine, `expected a shape-retry line, got: ${warn.lines.join(" | ")}`);
  assert.match(retryLine!, /declares no Test contract/);
});

test("generateAiSecurityReview (split): call B extraction prefers the fence containing the Test contract", async () => {
  await withFetchBodies(
    async (call) =>
      call === 1
        ? NARRATIVE_OK()
        : ok200(
            replyEnvelope(
              "```solidity\ncontract Helper {\n    function poke() public pure returns (uint256) { return 1; }\n}\n```\n\n```solidity\n" +
                TEST_CODE +
                "\n```",
              "stop",
            ),
          ),
    async (calls) => {
      const review = await generateAiSecurityReview("Target", "contract Target {}", []);
      assert.equal(review.source, "openrouter");
      assert.equal(review.foundryTestCode, TEST_CODE);
      // No corrective retry was needed — first code reply sufficed.
      assert.equal(calls(), 2);
    },
  );
});

test("generateAiSecurityReview (split): a helper-only fence from call B is a shape failure and retries correctively", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
      async (call) => {
        if (call === 1) return NARRATIVE_OK();
        if (call === 2) {
          return ok200(
            replyEnvelope(
              "```solidity\ncontract Helper {\n    function poke() public pure returns (uint256) { return 1; }\n}\n```",
              "stop",
            ),
          );
        }
        return CODE_OK();
      },
      async (calls) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "openrouter");
        assert.equal(review.foundryTestCode, TEST_CODE);
        assert.equal(calls(), 3);
      },
    );
  } finally {
    warn.restore();
  }
  const retryLine = warn.lines.find((l) => l.includes("test-code reply unusable"));
  assert.ok(retryLine, `expected a shape-retry line, got: ${warn.lines.join(" | ")}`);
  assert.match(retryLine!, /declares no Test contract/);
  assert.match(retryLine!, /no executable test function/);
});

test("generateAiSecurityReview (split): truncation on call B is named in logs with the code budget", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
      async (call) => {
        if (call === 1) return NARRATIVE_OK();
        if (call === 2) {
          return ok200(
            replyEnvelope(
              "Here is the adapted test:\n```solidity\n// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\nimport \"forge-std/Test.sol\";\n\ncontract PoC is Test {\n    function setUp() public {\n        vm.createSelectFork(vm.envString(\"POC_R",
              "length",
            ),
          );
        }
        return CODE_OK();
      },
      async (calls, bodies) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "openrouter");
        assert.equal(calls(), 3);
        const third = JSON.parse(bodies[2]!) as { messages: Array<{ content: string }> };
        const corrective = third.messages[third.messages.length - 1]!.content;
        assert.match(corrective, /cut off at the token limit/);
        assert.match(corrective, /more compact test/);
      },
    );
  } finally {
    warn.restore();
  }
  const retryLine = warn.lines.find((l) => l.includes("test-code reply unusable"));
  assert.ok(retryLine, `expected a shape-retry line, got: ${warn.lines.join(" | ")}`);
  assert.match(retryLine!, /truncated at max_tokens 16000/);
  assert.match(retryLine!, /finish_reason "length"/);
});

test("generateAiSecurityReview (split): an empty completion on call A is retried once, then succeeds", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
      async (call) => {
        if (call === 1) return ok200(replyEnvelope("", "stop"));
        if (call === 2) return NARRATIVE_OK();
        return CODE_OK();
      },
      async (calls) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "openrouter");
        assert.equal(calls(), 3);
      },
    );
  } finally {
    warn.restore();
  }
  assert.ok(
    warn.lines.some((l) => /narrative call returned no message content \(model test\/model\) — retrying once/.test(l)),
    `empty retry must be logged per call, got: ${warn.lines.join(" | ")}`,
  );
});

test("generateAiSecurityReview (split): an empty completion on call B is retried once, then succeeds", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
      async (call) => {
        if (call === 1) return NARRATIVE_OK();
        if (call === 2) return ok200(replyEnvelope("", "stop"));
        return CODE_OK();
      },
      async (calls) => {
        const review = await generateAiSecurityReview("Target", "contract Target {}", []);
        assert.equal(review.source, "openrouter");
        assert.equal(review.foundryTestCode, TEST_CODE);
        assert.equal(calls(), 3);
      },
    );
  } finally {
    warn.restore();
  }
  assert.ok(
    warn.lines.some((l) => /test code call returned no message content \(model test\/model\) — retrying once/.test(l)),
    `empty retry must be logged per call, got: ${warn.lines.join(" | ")}`,
  );
});

test("generateAiSecurityReview (split): empty completions twice on call A fall back, naming the empty retry", async () => {
  const warn = captureWarn();
  try {
    await withFetchBodies(
      async () => ok200(replyEnvelope("", "stop")),
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
  assert.match(fallback!, /failed call: narrative/);
  assert.match(fallback!, /empty-reply retry attempted and exhausted/);
  assert.match(fallback!, /OpenRouter returned no message content/);
});
test("review prompts label corrected detectors with their mechanism class and right template", () => {
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
    // Templates live in the TEST-CODE prompt in the split (the
    // narrative call never needed them).
    const { user } = buildAiReviewTestPrompt("Target", "contract Target {}", [
      finding(detector, `${detector} finding`, `${detector} summary`),
    ]);
    assert.ok(user.includes(label), `${detector}: prompt must carry "${label}"`);
    assert.ok(user.includes(`--- Template 1: ${template} ---`), `${detector}: prompt must inject ${template} first`);
    // The narrative prompt carries the same findings context (labels
    // included) through the shared context builder.
    const narrative = buildAiReviewPrompt("Target", "contract Target {}", [
      finding(detector, `${detector} finding`, `${detector} summary`),
    ]);
    assert.ok(narrative.user.includes(label), `${detector}: narrative prompt must carry "${label}"`);
  }
});
