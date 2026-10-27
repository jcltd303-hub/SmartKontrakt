// src/lib/audit/rpc-endpoints.ts
//
// Pluggable RPC endpoints with round-robin and cooldown (2026-10-27).
//
// Before this, the analysis path had no RPC configuration at all: every call
// walked a hardcoded list of public endpoints from the top, on every request, so
// a paid or keyed provider could not be plugged in and a rate-limited endpoint at
// position 0 was retried first forever.
//
// RPC_URLS is a comma-separated list. An entry may be prefixed with a chain to
// scope it (`ethereum:https://...`), and unprefixed entries serve every chain.
//
//   RPC_URLS="https://eth-mainnet.g.alchemy.com/v2/KEY,ethereum:https://mainnet.infura.io/v3/KEY"
//   RPC_MIN_INTERVAL_MS=50     # default 200 (5 req/s); a keyed provider takes far more
//
// Rotation is round-robin across calls, so a provider's quota is shared rather
// than exhausted in order. A failure puts an endpoint in cooldown and the next
// call starts elsewhere; a success clears it. Cooldowns are per process, which is
// what makes sharding multiply throughput rather than just splitting the list.

/** Statuses that mean "this endpoint is spent or broken", not "this request was wrong". */
const COOLDOWN_STATUSES = new Set([402, 403, 429, 500, 502, 503, 504]);

/** How long a failed endpoint is skipped. 429/402 quotas reset slowly; a 5xx may not. */
const COOLDOWN_MS_SPENT = 60_000;
const COOLDOWN_MS_BROKEN = 15_000;

export type RpcEndpoint = { url: string; chain: string | null };

export function parseRpcUrls(raw: string | undefined): RpcEndpoint[] {
  if (!raw) return [];
  const out: RpcEndpoint[] = [];
  const seen = new Set<string>();
  for (const part of raw.split(",")) {
    const entry = part.trim();
    if (!entry) continue;
    let chain: string | null = null;
    let url = entry;
    // `chain:https://...` — the scheme colon is followed by //, so only treat a
    // prefix as a chain when it does not look like a URL scheme.
    const m = entry.match(/^([a-zA-Z][\w-]*):(?!\/\/)(.+)$/);
    if (m && /^https?:\/\//.test(m[2] ?? "")) {
      chain = m[1]!.toLowerCase();
      url = m[2]!;
    }
    if (!/^https?:\/\//.test(url)) continue;
    const key = `${chain ?? "*"}|${url}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ url, chain });
  }
  return out;
}

export class RpcPool {
  private endpoints: RpcEndpoint[];
  private cursor = 0;
  private cooldownUntil = new Map<string, number>();
  private now: () => number;

  constructor(endpoints: RpcEndpoint[], now: () => number = Date.now) {
    this.endpoints = endpoints;
    this.now = now;
  }

  get size(): number {
    return this.endpoints.length;
  }

  /**
   * The order to try for this chain: configured endpoints first (round-robin from
   * the current cursor, healthy before cooling), then whatever built-in list the
   * caller had, minus duplicates. With no RPC_URLS this returns the built-in list
   * untouched, so an unconfigured install behaves exactly as before.
   */
  order(chain: string | null, builtIn: string[]): string[] {
    if (this.endpoints.length === 0) return builtIn;
    const t = this.now();
    const scoped = this.endpoints.filter((e) => e.chain === null || e.chain === chain);
    if (scoped.length === 0) return builtIn;
    const start = this.cursor++ % scoped.length;
    const rotated = [...scoped.slice(start), ...scoped.slice(0, start)];
    const healthy = rotated.filter((e) => (this.cooldownUntil.get(e.url) ?? 0) <= t);
    const cooling = rotated.filter((e) => (this.cooldownUntil.get(e.url) ?? 0) > t);
    // Cooling endpoints are last, not dropped: if every endpoint is spent, trying
    // a cooling one is better than not trying at all.
    const ordered = [...healthy, ...cooling].map((e) => e.url);
    const extras = builtIn.filter((u) => !ordered.includes(u));
    return [...ordered, ...extras];
  }

  /** Record the outcome of a request so the next call routes around it. */
  note(url: string, outcome: { ok: boolean; status?: number }): void {
    if (outcome.ok) {
      this.cooldownUntil.delete(url);
      return;
    }
    const status = outcome.status;
    if (status === undefined) {
      // Network error / timeout: may be transient, so a short cooldown.
      this.cooldownUntil.set(url, this.now() + COOLDOWN_MS_BROKEN);
      return;
    }
    if (!COOLDOWN_STATUSES.has(status)) return; // a 404 or a bad request is not the endpoint's fault
    const spent = status === 402 || status === 403 || status === 429;
    this.cooldownUntil.set(url, this.now() + (spent ? COOLDOWN_MS_SPENT : COOLDOWN_MS_BROKEN));
  }

  /** Test seam. */
  cooldownRemainingMs(url: string): number {
    return Math.max(0, (this.cooldownUntil.get(url) ?? 0) - this.now());
  }
}

/** Process-wide pool, built once from the environment. */
export const rpcPool = new RpcPool(parseRpcUrls(process.env.RPC_URLS));
