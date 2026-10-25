/**
 * Shared rate limiting + retry for every outbound call the pipeline makes
 * (Sourcify, public JSON-RPC, OpenRouter). Built for multi-day runs: the
 * pipeline would rather go slow and finish than hammer a provider, get
 * 429'd, and mark real contracts failed.
 *
 * Works in browser and on the server (Date.now + setTimeout only).
 */

/** Serializes acquisitions with a minimum spacing, so concurrent callers queue up instead of bursting. */
export class RateLimiter {
  private last = 0;
  private chain: Promise<void> = Promise.resolve();

  private intervalMs: number;

  constructor(intervalMs: number) {
    this.intervalMs = intervalMs;
  }

  acquire(): Promise<void> {
    const run = this.chain.then(async () => {
      const wait = this.last + this.intervalMs - Date.now();
      if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
      this.last = Date.now();
    });
    // Keep the chain alive past a single failure.
    this.chain = run.catch(() => undefined);
    return run;
  }
}

/** Conservative defaults. The 429 backoff in withRetry is the adaptive mechanism — these just keep us polite. */
export const rpcLimiter = new RateLimiter(200); // 5 JSON-RPC req/sec
export const sourcifyLimiter = new RateLimiter(500); // 2 Sourcify req/sec
// Paid account ($10 credit) — NOT the free tier, so this is 1/sec, not the
// free-tier trickle. 429 backoff still adapts if the provider throttles.
export const openRouterLimiter = new RateLimiter(1000); // 60 OpenRouter req/min

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export function isTransientError(err: unknown): boolean {
  if (err instanceof Error) {
    if (err.name === "AbortError" || err.name === "TimeoutError") return true;
    return /429|rate.?limit|too many|timeout|timed out|abort|network|fetch failed|econnreset|etimedout|econnrefused|socket hang up|503|502|500/i.test(err.message);
  }
  return false;
}

/**
 * Retry a fetch (or any async fn) on transient failures: 429 / 5xx, network
 * errors, timeouts. Honors the server's Retry-After header when present.
 * `retryOn` lets a caller treat domain errors as transient too (the pipeline
 * retries every analyze failure because every queued address is a contract).
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  opts: {
    retries?: number;
    baseDelayMs?: number;
    maxDelayMs?: number;
    retryOn?: (err: unknown) => boolean;
  } = {},
): Promise<T> {
  const retries = opts.retries ?? 3;
  const base = opts.baseDelayMs ?? 1000;
  const max = opts.maxDelayMs ?? 30_000;
  let lastErr: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fn();
      if (res instanceof Response && (res.status === 429 || res.status >= 500)) {
        const retryAfter = Number(res.headers.get("retry-after"));
        const wait = Number.isFinite(retryAfter) && retryAfter > 0
          ? Math.min(max, retryAfter * 1000)
          : Math.min(max, base * 2 ** attempt);
        if (attempt < retries) {
          await sleep(wait);
          continue;
        }
        throw new Error(`HTTP ${res.status}`);
      }
      return res;
    } catch (err) {
      lastErr = err;
      if (attempt >= retries) throw err;
      if (opts.retryOn ? !opts.retryOn(err) : !isTransientError(err)) throw err;
      await sleep(Math.min(max, base * 2 ** attempt));
    }
  }
  throw lastErr;
}
