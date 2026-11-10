import { OPENROUTER_API_URL, resolveOpenRouterConfig } from "./ai-review.server.ts";

/**
 * OpenRouter usage + liveness, for the workbench's AI surfaces.
 *
 * Two calls, both against the server-side key (never sent to the
 * client; only the parsed numbers below cross the wire):
 *
 *   1. GET /auth/key — the key's own ledger: total + daily usage in
 *      USD, the credit limit and what remains of it, whether
 *      OpenRouter still classifies the account as free tier, and the
 *      key's rate limit. This is how "funded free tier" is verified
 *      rather than assumed: a topped-up account shows a limit and a
 *      limit_remaining; a pure free-tier key shows limit null.
 *   2. A one-shot probe completion on the configured chat model
 *      (max_tokens 8, a free model, so $0) — proves end-to-end that
 *      this server can actually make calls right now, and times it.
 *
 * Both halves fail soft and independently: a dead key endpoint still
 * returns the probe result and vice versa. Errors are data, never
 * thrown — the UI renders them as-is.
 */

/** OpenRouter key-info endpoint — defined in the central config
 * (src/lib/config.mjs) and imported here (the local binding is used below);
 * re-exported for existing importers. */
import { OPENROUTER_KEY_URL } from "../config.ts";
export { OPENROUTER_KEY_URL };

export type OpenRouterKeyInfo = {
  label: string | null;
  usage: number | null;
  usageDaily: number | null;
  usageWeekly: number | null;
  usageMonthly: number | null;
  limit: number | null;
  limitRemaining: number | null;
  isFreeTier: boolean | null;
  rateLimitRequests: number | null;
  rateLimitInterval: string | null;
};

export type OpenRouterUsage = {
  /** A real (non-placeholder) OPENROUTER_API_KEY is configured. */
  configured: boolean;
  /** Parsed /auth/key ledger; null when the call failed. */
  key: OpenRouterKeyInfo | null;
  /** Why the ledger is missing, when it is. */
  keyError: string | null;
  probe: {
    ok: boolean;
    /** The chat-lane model the probe ran against. */
    model: string;
    latencyMs: number | null;
    error: string | null;
  };
};

type FetchImpl = typeof fetch;

function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function str(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/** Parse a GET /auth/key body (`{ data: { … } }`). Unknown → nulls. */
export function parseOpenRouterKeyInfo(body: unknown): OpenRouterKeyInfo {
  const data =
    body !== null && typeof body === "object" && "data" in body
      ? (body as { data: unknown }).data
      : body;
  const d: Record<string, unknown> =
    data !== null && typeof data === "object" ? (data as Record<string, unknown>) : {};
  const rate =
    d.rate_limit !== null && typeof d.rate_limit === "object"
      ? (d.rate_limit as Record<string, unknown>)
      : {};
  return {
    label: str(d.label),
    usage: num(d.usage),
    usageDaily: num(d.usage_daily),
    usageWeekly: num(d.usage_weekly),
    usageMonthly: num(d.usage_monthly),
    limit: num(d.limit),
    limitRemaining: num(d.limit_remaining),
    isFreeTier: typeof d.is_free_tier === "boolean" ? d.is_free_tier : null,
    rateLimitRequests: num(rate.requests),
    rateLimitInterval: str(rate.interval),
  };
}

async function fetchWithTimeout(
  fetchImpl: FetchImpl,
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function errorText(err: unknown): string {
  if (err instanceof Error) {
    return err.name === "AbortError" ? "request timed out" : err.message;
  }
  return String(err);
}

export async function getOpenRouterUsage(
  env: NodeJS.ProcessEnv = process.env,
  fetchImpl: FetchImpl = fetch,
): Promise<OpenRouterUsage> {
  const { apiKey, model } = resolveOpenRouterConfig(env, "chat");
  if (!apiKey) {
    return {
      configured: false,
      key: null,
      keyError: null,
      probe: { ok: false, model, latencyMs: null, error: "no OpenRouter API key configured" },
    };
  }
  const headers = {
    Authorization: `Bearer ${apiKey}`,
    "Content-Type": "application/json",
  };

  let key: OpenRouterKeyInfo | null = null;
  let keyError: string | null = null;
  try {
    const res = await fetchWithTimeout(
      fetchImpl,
      OPENROUTER_KEY_URL,
      { method: "GET", headers },
      15_000,
    );
    if (!res.ok) {
      keyError = `key endpoint answered HTTP ${res.status}`;
    } else {
      key = parseOpenRouterKeyInfo(await res.json());
    }
  } catch (err) {
    keyError = errorText(err);
  }

  let probe: OpenRouterUsage["probe"] = { ok: false, model, latencyMs: null, error: null };
  const started = Date.now();
  try {
    const res = await fetchWithTimeout(
      fetchImpl,
      OPENROUTER_API_URL,
      {
        method: "POST",
        headers,
        body: JSON.stringify({
          model,
          messages: [{ role: "user", content: "Reply with the single word: ok" }],
          max_tokens: 8,
          temperature: 0,
        }),
      },
      60_000,
    );
    const latencyMs = Date.now() - started;
    if (!res.ok) {
      let detail = "";
      try {
        const body: unknown = await res.json();
        const msg = (body as { error?: { message?: unknown } })?.error?.message;
        if (typeof msg === "string") detail = `: ${msg.slice(0, 200)}`;
      } catch {
        /* body stays unparsed — the status alone is the report */
      }
      probe = { ok: false, model, latencyMs, error: `HTTP ${res.status}${detail}` };
    } else {
      const body: unknown = await res.json();
      const choices = (body as { choices?: unknown })?.choices;
      probe =
        Array.isArray(choices) && choices.length > 0
          ? { ok: true, model, latencyMs, error: null }
          : { ok: false, model, latencyMs, error: "reply carried no choices" };
    }
  } catch (err) {
    probe = { ok: false, model, latencyMs: Date.now() - started, error: errorText(err) };
  }

  return { configured: true, key, keyError, probe };
}
