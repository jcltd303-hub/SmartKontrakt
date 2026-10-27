// pipeline-worker/llm-health.ts
//
// LLM health as a COUNTER, not a log line (2026-10-27).
//
// The worker already records `aiStatus` per saved record, but that is only
// visible by reading the database afterwards, one row at a time. Whether the
// model is actually working during a run was answerable only by watching stdout
// — which means nobody finds out until the run is over and the narratives are
// empty.
//
// This keeps a per-run tally that /status can return, and a verdict that says in
// one word whether the LLM path is healthy. The distinctions matter:
//
//   unavailable — no OPENROUTER_API_KEY. Not a fault, a configuration state;
//                 the run is static-only and says so.
//   error       — the call was attempted and failed (HTTP error, timeout, a
//                 reply that failed the output contract).
//   empty       — the call succeeded but produced nothing usable. This is the
//                 quiet failure: a 200 with an empty body, or a narrative that
//                 the contract rejected, looks like success in a log.
//   ok          — usable text.
//
// A run that is mostly `empty` is as broken as one that is mostly `error`, and
// the tally is what makes that visible.

export type LlmOutcome = "ok" | "empty" | "error" | "unavailable";

export type LlmHealth = {
  /** Calls attempted (every outcome, including unavailable). */
  calls: number;
  ok: number;
  empty: number;
  error: number;
  unavailable: number;
  /** Consecutive failures (error or empty) — the thing that signals a break. */
  consecutiveFailures: number;
  /** The last failure message, kept short for /status. */
  lastError: string | null;
  /** ISO timestamp of the last usable reply. */
  lastOkAt: string | null;
};

export function newLlmHealth(): LlmHealth {
  return {
    calls: 0,
    ok: 0,
    empty: 0,
    error: 0,
    unavailable: 0,
    consecutiveFailures: 0,
    lastError: null,
    lastOkAt: null,
  };
}

/** Record one second-pass outcome. `detail` is only kept for failures. */
export function recordLlm(
  health: LlmHealth,
  outcome: LlmOutcome,
  detail?: string,
  now: Date = new Date(),
): LlmHealth {
  health.calls += 1;
  if (outcome === "ok") {
    health.ok += 1;
    health.consecutiveFailures = 0;
    health.lastOkAt = now.toISOString();
    return health;
  }
  if (outcome === "unavailable") {
    // Not a failure: no key is a static-only run, and counting it as a
    // failure would trip the breaker on a correctly configured run.
    health.unavailable += 1;
    return health;
  }
  if (outcome === "empty") health.empty += 1;
  else health.error += 1;
  health.consecutiveFailures += 1;
  if (detail) health.lastError = detail.slice(0, 300);
  return health;
}

export type LlmVerdict = {
  /** One word for a dashboard or a log line. */
  state: "smooth" | "degraded" | "dead" | "off";
  /** One line saying why, actionable enough to fix without more data. */
  reason: string;
};

/**
 * Judge the run.
 *
 * Thresholds, chosen to be conservative rather than clever:
 *   - 3 consecutive failures  → `dead`   (the same count the PoC breaker uses)
 *   - any failure above 20%   → `degraded`
 *   - all unavailable         → `off`    (no key: expected, not a fault)
 */
export function llmVerdict(health: LlmHealth): LlmVerdict {
  const attempted = health.ok + health.empty + health.error;
  if (attempted === 0) {
    if (health.unavailable > 0) {
      return {
        state: "off",
        reason: "no OPENROUTER_API_KEY — every entry is static-only, and the narratives are the fallback text",
      };
    }
    return { state: "smooth", reason: "no LLM calls yet in this run" };
  }
  if (health.consecutiveFailures >= 3) {
    return {
      state: "dead",
      reason: `${health.consecutiveFailures} consecutive failures — last: ${health.lastError ?? "unknown"}${health.lastOkAt ? ` (last good reply ${health.lastOkAt})` : " (no good reply yet this run)"}`,
    };
  }
  const failureRate = (health.empty + health.error) / attempted;
  if (failureRate > 0.2) {
    return {
      state: "degraded",
      reason: `${(failureRate * 100).toFixed(0)}% of ${attempted} calls produced no usable text (${health.empty} empty, ${health.error} error)`,
    };
  }
  return {
    state: "smooth",
    reason: `${health.ok}/${attempted} usable replies${health.empty + health.error > 0 ? `, ${health.empty + health.error} failed` : ""}`,
  };
}
