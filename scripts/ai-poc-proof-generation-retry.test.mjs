import { test } from "node:test";
import assert from "node:assert/strict";
import {
  GENERATION_BACKOFF_MS,
  GENERATION_MAX_ATTEMPTS,
  generateWithRetry,
  isGenerationFallback,
} from "./ai-poc-proof/generation-retry.mjs";

const noSleep = async () => {};

function sleepRecorder() {
  const waits = [];
  return {
    waits,
    sleep: async (ms) => {
      waits.push(ms);
    },
  };
}

/** A generate() stub that walks a fixed sequence of results. */
function scripted(sequence) {
  let i = 0;
  return async () => sequence[Math.min(i++, sequence.length - 1)];
}

test("fallback detection: only a non-openrouter, non-fatal result is a fallback", () => {
  assert.equal(isGenerationFallback({ source: "openrouter" }), false);
  assert.equal(isGenerationFallback({ source: "template" }), true);
  assert.equal(isGenerationFallback({ source: "template-fallback" }), true);
  assert.equal(isGenerationFallback({ source: undefined }), true);
  // A bridge crash is infra, not a fallback — it must not be retried
  // into a different answer.
  assert.equal(isGenerationFallback({ fatal: "bridge died", source: "template" }), false);
  assert.equal(isGenerationFallback(null), false);
  assert.equal(isGenerationFallback(undefined), false);
});

test("retry policy constants: 3 attempts total, 5s then 15s backoff", () => {
  assert.equal(GENERATION_MAX_ATTEMPTS, 3);
  assert.deepEqual(GENERATION_BACKOFF_MS, [5_000, 15_000]);
});

test("retry: first-attempt success makes exactly one attempt and never sleeps", async () => {
  const { waits, sleep } = sleepRecorder();
  const out = await generateWithRetry(
    async () => ({ source: "openrouter", foundryTestCode: "CODE" }),
    { sleep },
  );
  assert.equal(out.attempts, 1);
  assert.equal(out.fellBack, false);
  assert.equal(out.result.foundryTestCode, "CODE");
  assert.deepEqual(waits, []);
});

test("retry: two fallbacks then success = 3 attempts, with the 5s/15s backoff between them", async () => {
  const { waits, sleep } = sleepRecorder();
  const gen = scripted([
    { source: "template" },
    { source: "template" },
    { source: "openrouter", foundryTestCode: "CODE" },
  ]);
  const out = await generateWithRetry(gen, { sleep });
  assert.equal(out.attempts, 3);
  assert.equal(out.fellBack, false);
  assert.equal(out.result.source, "openrouter");
  assert.deepEqual(waits, [...GENERATION_BACKOFF_MS]);
});

test("retry: a persistent fallback exhausts the budget and reports fellBack with the last result", async () => {
  const { waits, sleep } = sleepRecorder();
  let calls = 0;
  const out = await generateWithRetry(
    async () => {
      calls += 1;
      return { source: "template" };
    },
    { sleep },
  );
  assert.equal(calls, GENERATION_MAX_ATTEMPTS);
  assert.equal(out.attempts, GENERATION_MAX_ATTEMPTS);
  assert.equal(out.fellBack, true);
  assert.equal(out.result.source, "template");
  assert.deepEqual(waits, [...GENERATION_BACKOFF_MS]);
});

test("retry: a fatal bridge result comes back immediately — no retries, no sleeps", async () => {
  const { waits, sleep } = sleepRecorder();
  let calls = 0;
  const out = await generateWithRetry(
    async () => {
      calls += 1;
      return { fatal: "boom" };
    },
    { sleep },
  );
  assert.equal(calls, 1);
  assert.equal(out.attempts, 1);
  assert.equal(out.fellBack, false);
  assert.equal(out.result.fatal, "boom");
  assert.deepEqual(waits, []);
});

test("retry: a throwing generate() propagates untouched (infra is not converted into retries)", async () => {
  let calls = 0;
  await assert.rejects(
    () =>
      generateWithRetry(
        async () => {
          calls += 1;
          throw new Error("bridge returned non-JSON");
        },
        { sleep: noSleep },
      ),
    /bridge returned non-JSON/,
  );
  assert.equal(calls, 1);
});

test("retry: onRetry fires once per retry with the attempt, the wait, and the fallback source", async () => {
  const events = [];
  const gen = scripted([{ source: "template" }, { source: "openrouter" }]);
  const out = await generateWithRetry(gen, {
    sleep: noSleep,
    onRetry: (e) => events.push(e),
  });
  assert.equal(out.attempts, 2);
  assert.equal(events.length, 1);
  assert.equal(events[0].attempt, 1);
  assert.equal(events[0].nextAttempt, 2);
  assert.equal(events[0].waitMs, GENERATION_BACKOFF_MS[0]);
  assert.equal(events[0].source, "template");
});

test("retry: a caller-supplied maxAttempts is honored", async () => {
  let calls = 0;
  const out = await generateWithRetry(
    async () => {
      calls += 1;
      return { source: "template" };
    },
    { sleep: noSleep, maxAttempts: 2 },
  );
  assert.equal(calls, 2);
  assert.equal(out.attempts, 2);
  assert.equal(out.fellBack, true);
});
