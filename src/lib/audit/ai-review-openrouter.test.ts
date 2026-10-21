import test from "node:test";
import assert from "node:assert/strict";
import {
  extractJsonContent,
  resolveOpenRouterConfig,
  resolveOpenRouterModel,
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
