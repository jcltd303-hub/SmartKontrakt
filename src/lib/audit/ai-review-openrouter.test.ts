import test from "node:test";
import assert from "node:assert/strict";
import {
  extractJsonContent,
  resolveOpenRouterConfig,
  resolveOpenRouterModel,
  OPENROUTER_MODELS,
  DEFAULT_OPENROUTER_MODEL,
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
