import test from "node:test";
import assert from "node:assert/strict";

import { llmVerdict, newLlmHealth, recordLlm } from "../../../pipeline-worker/llm-health.ts";

/**
 * LLM health as a counter (2026-10-27).
 *
 * The worker recorded `aiStatus` per saved row, so whether the model was working
 * was only visible by reading the database afterwards or watching stdout. These
 * pin the tally and the verdict, including the failure the logs hide: a 200 that
 * produces no usable text.
 */

test("a fresh run has no verdict to give", () => {
  const h = newLlmHealth();
  assert.equal(llmVerdict(h).state, "smooth");
  assert.match(llmVerdict(h).reason, /no LLM calls yet/);
});

test("no key is 'off', not a failure", () => {
  const h = newLlmHealth();
  recordLlm(h, "unavailable");
  recordLlm(h, "unavailable");
  const v = llmVerdict(h);
  assert.equal(v.state, "off");
  assert.match(v.reason, /OPENROUTER_API_KEY/);
  assert.equal(h.consecutiveFailures, 0, "an unconfigured run must not trip the breaker");
});

test("a run of good replies is smooth", () => {
  const h = newLlmHealth();
  for (let i = 0; i < 10; i++) recordLlm(h, "ok");
  assert.equal(llmVerdict(h).state, "smooth");
  assert.equal(h.ok, 10);
  assert.ok(h.lastOkAt);
});

test("empty text counts as a failure, not a success", () => {
  // The quiet one: HTTP 200, a reply the output contract rejected, a fallback
  // narrative left in place. In a log this looks like a success.
  const h = newLlmHealth();
  recordLlm(h, "ok");
  recordLlm(h, "empty", "status=ok, no usable text");
  assert.equal(h.ok, 1);
  assert.equal(h.empty, 1);
  assert.equal(h.consecutiveFailures, 1);
});

test("three consecutive failures is dead, and the reason carries the last error", () => {
  const h = newLlmHealth();
  recordLlm(h, "ok");
  recordLlm(h, "error", "429 rate limited");
  recordLlm(h, "empty", "no usable text");
  recordLlm(h, "error", "502 bad gateway");
  const v = llmVerdict(h);
  assert.equal(v.state, "dead");
  assert.match(v.reason, /3 consecutive/);
  assert.match(v.reason, /502/);
});

test("a good reply resets the streak, but not the rate", () => {
  const h = newLlmHealth();
  recordLlm(h, "error", "boom");
  recordLlm(h, "error", "boom");
  recordLlm(h, "ok");
  assert.equal(h.consecutiveFailures, 0, "the streak is broken by the good reply");
  // Still degraded: 2 of 3 calls failed, and the streak is only one of the two
  // ways a run is unhealthy. Resetting it must not paper over the rate.
  assert.equal(llmVerdict(h).state, "degraded");
  for (let i = 0; i < 20; i++) recordLlm(h, "ok");
  assert.equal(llmVerdict(h).state, "smooth", "the rate recovers as good replies accumulate");
});

test("a high failure rate is degraded even without a streak", () => {
  const h = newLlmHealth();
  for (let i = 0; i < 4; i++) recordLlm(h, "ok");
  recordLlm(h, "empty", "x");
  recordLlm(h, "ok");
  recordLlm(h, "error", "y");
  const v = llmVerdict(h);
  assert.equal(v.state, "degraded");
  // 2 failures out of 7 attempted.
  assert.match(v.reason, /29%/);
});

test("unavailable calls do not dilute the failure rate", () => {
  // A run that starts unconfigured and then gets a key: the early
  // `unavailable` rows must not count as attempted calls.
  const h = newLlmHealth();
  for (let i = 0; i < 20; i++) recordLlm(h, "unavailable");
  recordLlm(h, "ok");
  recordLlm(h, "ok");
  assert.equal(llmVerdict(h).state, "smooth");
});

test("lastError is capped so /status stays readable", () => {
  const h = newLlmHealth();
  recordLlm(h, "error", "x".repeat(1000));
  assert.ok((h.lastError ?? "").length <= 300);
});
