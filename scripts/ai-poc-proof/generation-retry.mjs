// generation-retry.mjs — the live-mode generation retry policy for
// the ai-poc-proof runner, extracted from run.mjs so it is
// unit-testable without an OpenRouter key
// (scripts/ai-poc-proof-generation-retry.test.mjs).
//
// Why this exists: on the 2026-10-23 live run, 21 of 46 types were
// lost to a SINGLE transient generation fallback each — the app fell
// back to the template review (source != "openrouter"), no AI PoC was
// generated, and the runner recorded the type as done. One flaky
// upstream minute must not eat half the suite, so the generation step
// — and only the generation step — retries.
//
// What does NOT retry:
//  - a bridge crash ({fatal}) is an infra failure, not a fallback;
//  - a generated PoC that fails compile/assertion is a RESULT.
// Retrying either would manufacture a different answer instead of
// measuring the first one. The one compile repair stays in run.mjs,
// unchanged.

/** Total generation attempts per type in live mode (1 initial + 2 retries). */
export const GENERATION_MAX_ATTEMPTS = 3;

/**
 * Backoff between attempts, ms: the wait after attempt N falls back
 * is entry N-1. 5s then 15s — long enough for a rate-limit / upstream
 * blip to clear, short enough that a type whose generation never
 * lands costs ~20s of waiting on top of its generation calls.
 */
export const GENERATION_BACKOFF_MS = [5_000, 15_000];

/**
 * A generation result is a FALLBACK when the app produced the
 * template review instead of an AI review: any source other than
 * "openrouter". A {fatal} bridge result is NOT a fallback — it is a
 * crash, and the caller files it as infra without retrying. Anything
 * that is not a result object at all is not a fallback either (the
 * bridge harness throws before such a value could reach here).
 */
export function isGenerationFallback(gen) {
  if (!gen || typeof gen !== "object") return false;
  if (gen.fatal) return false;
  return gen.source !== "openrouter";
}

const defaultSleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Call `generate(attempt)` until it returns a non-fallback result or
 * the attempt budget runs out. A throw from `generate` propagates
 * untouched (the caller files it as infra, exactly as before). The
 * `sleep` and `onRetry` options are injectable for tests; `onRetry`
 * fires after a fallback when another attempt remains.
 *
 * Returns { result, attempts, fellBack } — `attempts` is the honest
 * count the runner records on the type's result entry, and when
 * `fellBack` is true `result` is the last fallback seen.
 */
export async function generateWithRetry(generate, opts = {}) {
  const maxAttempts = opts.maxAttempts ?? GENERATION_MAX_ATTEMPTS;
  const backoffMs = opts.backoffMs ?? GENERATION_BACKOFF_MS;
  const sleep = opts.sleep ?? defaultSleep;
  let attempts = 0;
  let last = null;
  while (attempts < maxAttempts) {
    attempts += 1;
    last = await generate(attempts);
    if (!isGenerationFallback(last)) {
      return { result: last, attempts, fellBack: false };
    }
    if (attempts < maxAttempts) {
      const waitMs = backoffMs[Math.min(attempts - 1, backoffMs.length - 1)] ?? 0;
      opts.onRetry?.({
        attempt: attempts,
        nextAttempt: attempts + 1,
        waitMs,
        source: last?.source ?? null,
      });
      if (waitMs > 0) await sleep(waitMs);
    }
  }
  return { result: last, attempts, fellBack: true };
}
