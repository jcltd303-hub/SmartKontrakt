// src/lib/poc-runs.ts
//
// Task 2 of the Local PoC Runner plan: durable, retry-safe persistence
// for terminal Foundry PoC runs.
//
// Execution and persistence are separate: a run executes once (Task 1
// companion), and saving can be retried without rerunning. The retry
// must preserve the ORIGINAL result.
//
// Retry mechanism (409-tolerant, NOT ON CONFLICT): the save is a plain
// single-row INSERT with no `?on_conflict` parameter. A retry of an
// already-saved run hits the primary key and PostgREST answers
// HTTP 409 (unique violation); savePocRun treats 409 as success
// ("already saved") because the duplicate insert is rejected and the
// original row is untouched. The test is never re-executed by a retry,
// and the original insert is never overwritten.
//
// Why not ON CONFLICT / ignore-duplicates: Postgres RLS makes that
// combination incompatible with an insert-only table. Verified in
// PGlite (real Postgres semantics): (1) INSERT ... ON CONFLICT as anon
// fails with "permission denied" unless anon also has SELECT;
// (2) with SELECT granted but no SELECT policy, the ON CONFLICT insert
// fails with "new row violates row-level security policy" — ON
// CONFLICT needs a SELECT policy (USING) to see conflicting rows, and
// a permissive SELECT policy would let anon read rows, defeating
// insert-only. The 409-tolerant plain INSERT needs only GRANT INSERT
// + the INSERT policy, so insert-only RLS stays intact.
//
// Zero imports: global fetch / URL / atob only. Mirrors the key rules
// in src/lib/supabase.ts (assertBrowserKey, https-only, publishable /
// anon keys only) without importing it, so this module stays usable
// from any client context.

export type PocRunStatus = "passed" | "failed" | "error" | "timed_out" | "skipped" | "no_tests" | "unadapted";

export type PocRunResult = {
  /** UUID identifying this run. Stable across save retries. */
  id: string;
  /** The Foundry test source that was executed. */
  source: string;
  status: PocRunStatus;
  /** ISO 8601 timestamp when execution started. */
  startedAt: string;
  /** ISO 8601 timestamp when execution finished. Must be >= startedAt. */
  finishedAt: string;
  /** Wall-clock execution time in milliseconds. */
  durationMs: number;
  /** EVM chain id the run targeted. */
  chainId: number;
  /** Process exit code, or null when the process never exited (timeout / kill). */
  exitCode: number | null;
  /** Bounded combined stdout/stderr. */
  output: string;
  /** True when output was cut at the cap. */
  truncated: boolean;
};

/** Browser Supabase configuration for PoC run saves. The table is always `poc_runs`. */
export type PocRunSupabaseConfig = {
  url: string;
  anonKey: string;
  enabled: boolean;
};

const POC_RUNS_TABLE = "poc_runs";
const MAX_SOURCE_CHARS = 120_000;
const MAX_OUTPUT_CHARS = 1_000_000;
const SAVE_TIMEOUT_MS = 30_000;

const POC_RUN_STATUSES: ReadonlySet<string> = new Set(["passed", "failed", "error", "timed_out", "skipped", "no_tests", "unadapted"]);
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * Browser-key guard (mirrors src/lib/supabase.ts assertBrowserKey).
 * Rejects secret keys (sb_secret_ prefix) and JWTs whose payload role
 * is service_role. Publishable sb_publishable_ keys are not JWTs and
 * are accepted.
 */
function assertBrowserKey(key: string): void {
  let serviceRole = key.startsWith("sb_secret_");
  try {
    serviceRole ||= JSON.parse(atob(key.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))).role === "service_role";
  } catch {
    /* Publishable keys are not JWTs. */
  }
  if (!key || serviceRole) throw new Error("PoC run saving requires a publishable or anon key; keep secret keys on the server.");
}

/** Validate a PoC run result. Throws a clear Error on the first violation. */
export function validatePocRunResult(result: PocRunResult): void {
  if (!result || typeof result !== "object") throw new Error("PoC run result must be an object.");
  if (typeof result.id !== "string" || !UUID_RE.test(result.id)) throw new Error("PoC run id must be a valid UUID.");
  if (typeof result.source !== "string") throw new Error("PoC run source must be a string.");
  if (result.source.length > MAX_SOURCE_CHARS) {
    throw new Error(`PoC run source exceeds the ${MAX_SOURCE_CHARS}-character limit; refusing to save rather than silently truncating.`);
  }
  if (typeof result.status !== "string" || !POC_RUN_STATUSES.has(result.status)) {
    throw new Error("PoC run status must be one of passed, failed, error, timed_out, skipped, no_tests, unadapted.");
  }
  const started = Date.parse(result.startedAt);
  const finished = Date.parse(result.finishedAt);
  if (Number.isNaN(started)) throw new Error("PoC run startedAt must be a valid ISO date.");
  if (Number.isNaN(finished)) throw new Error("PoC run finishedAt must be a valid ISO date.");
  if (finished < started) throw new Error("PoC run finishedAt must not be before startedAt.");
  if (typeof result.durationMs !== "number" || !Number.isInteger(result.durationMs) || result.durationMs < 0) {
    throw new Error("PoC run durationMs must be an integer >= 0.");
  }
  if (typeof result.chainId !== "number" || !Number.isInteger(result.chainId)) {
    throw new Error("PoC run chainId must be an integer.");
  }
  if (result.exitCode !== null && (typeof result.exitCode !== "number" || !Number.isInteger(result.exitCode))) {
    throw new Error("PoC run exitCode must be an integer or null.");
  }
  if (typeof result.output !== "string") throw new Error("PoC run output must be a string.");
  if (result.output.length > MAX_OUTPUT_CHARS) {
    throw new Error(`PoC run output exceeds the ${MAX_OUTPUT_CHARS}-character limit; refusing to save rather than silently truncating.`);
  }
  if (typeof result.truncated !== "boolean") throw new Error("PoC run truncated must be a boolean.");
}

/**
 * Save one terminal PoC run result to the `poc_runs` table.
 * Idempotent: retrying with the same result (same UUID) re-issues the
 * plain INSERT; PostgREST answers 409 for the duplicate primary key,
 * which is treated as success ("already saved") — the duplicate insert
 * is rejected, so the original row is never overwritten. The test is
 * never re-executed by a retry. Other non-OK responses throw an Error
 * including the HTTP status.
 */
export async function savePocRun(result: PocRunResult, config: PocRunSupabaseConfig): Promise<void> {
  if (!config.enabled) throw new Error("Supabase not configured: enable Supabase sync to save PoC runs.");
  validatePocRunResult(result);
  let url: URL;
  try {
    url = new URL(config.url);
  } catch {
    throw new Error("Supabase URL is invalid.");
  }
  if (url.protocol !== "https:") throw new Error("Supabase URL must use https://");
  assertBrowserKey(config.anonKey);
  const row = {
    id: result.id,
    source: result.source,
    status: result.status,
    started_at: result.startedAt,
    finished_at: result.finishedAt,
    duration_ms: result.durationMs,
    chain_id: result.chainId,
    exit_code: result.exitCode,
    output: result.output,
    truncated: result.truncated,
  };
  const res = await fetch(`${url.origin}/rest/v1/${POC_RUNS_TABLE}`, {
    method: "POST",
    signal: AbortSignal.timeout(SAVE_TIMEOUT_MS),
    headers: {
      apikey: config.anonKey,
      ...(!config.anonKey.startsWith("sb_publishable_") ? { Authorization: `Bearer ${config.anonKey}` } : {}),
      "Content-Type": "application/json",
      Prefer: "return=minimal",
    },
    body: JSON.stringify([row]),
  });
  // 409 = duplicate primary key: this exact run was already saved by an
  // earlier attempt. The duplicate insert was rejected, so the original
  // row is preserved; treat the retry as success.
  if (res.status === 409) return;
  if (!res.ok) throw new Error(`Supabase PoC run save failed (HTTP ${res.status}). Check the table and RLS policies.`);
}
