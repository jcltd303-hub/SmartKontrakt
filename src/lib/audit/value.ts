/**
 * Address value in USD — the "value at risk" of a target.
 *
 * Combines three keyless sources so no API key is required:
 *  - native coin balance, over public JSON-RPC (`eth_getBalance`), any chain;
 *  - ERC-20 token balances + per-token USD rates, from Blockscout's REST API;
 *  - the chain's native USD price, from Blockscout `/api/v2/stats`.
 * A DefiLlama pass prices any token Blockscout left unpriced.
 *
 * The one rule that matters: **unknown is not zero.** `complete` is true only
 * when every provider we need answered, so `isZeroValue()` — the pre-run skip —
 * can never fire on a provider outage or a chain we cannot see tokens on.
 */
import { rpcLimiter } from "./rate-limit.ts";
import { fetchNativeBalance, nativeSymbol, normalizeChainId, rpcUrlsForChain, type NativeBalance } from "./balance.ts";

export type TokenHolding = {
  kind: "native" | "erc20";
  /** Token contract address; null for the native coin. */
  address: string | null;
  symbol: string;
  name: string | null;
  decimals: number;
  /** Raw units as a decimal string (never a float — token amounts exceed 2^53). */
  raw: string;
  /** Whole tokens, for display only. */
  amount: number;
  priceUsd: number | null;
  valueUsd: number | null;
  /** Where the price came from ("blockscout" | "defillama"). */
  priceSource: string | null;
};

export type AddressValue = {
  address: string;
  chainId: number;
  symbol: string;
  nativeWei: string | null;
  nativeUsd: number | null;
  totalUsd: number;
  holdings: TokenHolding[];
  priced: number;
  unpriced: number;
  sources: string[];
  /** True only when every provider answered — a 0 total is trustworthy only then. */
  complete: boolean;
  notes: string[];
  valuedAt: string;
};

/** Chains we can enumerate token balances on. Absent chain => tokens unknown. */
export const BLOCKSCOUT_HOSTS: Record<number, string> = {
  1: "https://eth.blockscout.com",
  10: "https://optimism.blockscout.com",
  100: "https://gnosis.blockscout.com",
  137: "https://polygon.blockscout.com",
  8453: "https://base.blockscout.com",
  42161: "https://arbitrum.blockscout.com",
};

const DEFILLAMA_NATIVE_ID: Record<number, string> = {
  1: "coingecko:ethereum",
  10: "coingecko:ethereum",
  8453: "coingecko:ethereum",
  42161: "coingecko:ethereum",
  137: "coingecko:polygon-ecosystem-token",
  56: "coingecko:binancecoin",
  100: "coingecko:xdai",
};

/** Blockscout chain slugs, for DefiLlama's `<chain>:<address>` coin keys. */
const DEFILLAMA_CHAIN_SLUG: Record<number, string> = {
  1: "ethereum", 10: "optimism", 137: "polygon", 8453: "base", 42161: "arbitrum", 56: "bsc", 100: "xdai",
};

/** Whole-token amount from raw units and decimals (display only). */
export function tokenAmount(raw: string, decimals: number): number {
  try {
    const n = Number(raw);
    if (!Number.isFinite(n)) return 0;
    return n / 10 ** decimals;
  } catch {
    return 0;
  }
}

/** USD value of `amount` whole tokens at `priceUsd`; null when either is unknown. */
export function usdValue(amount: number, priceUsd: number | null): number | null {
  if (priceUsd === null || !Number.isFinite(priceUsd)) return null;
  if (!Number.isFinite(amount)) return null;
  return amount * priceUsd;
}

/** Compact USD display: $1.23, $1.2k, $3.4M. */
export function formatUsd(value: number | null | undefined): string | null {
  if (value === null || value === undefined || !Number.isFinite(value)) return null;
  const abs = Math.abs(value);
  if (abs >= 1_000_000_000) return `$${(value / 1_000_000_000).toFixed(2)}B`;
  if (abs >= 1_000_000) return `$${(value / 1_000_000).toFixed(2)}M`;
  if (abs >= 1_000) return `$${(value / 1_000).toFixed(2)}k`;
  if (abs >= 1) return `$${value.toFixed(2)}`;
  if (abs === 0) return "$0.00";
  return `$${value.toPrecision(2)}`;
}

/** Sum the priced holdings. Unpriced holdings contribute nothing but are counted. */
export function totalUsdOf(holdings: TokenHolding[]): number {
  return holdings.reduce((sum, h) => sum + (h.valueUsd ?? 0), 0);
}

/**
 * The pre-run skip condition: a total of exactly zero that we can TRUST.
 * An incomplete valuation (provider down, chain we cannot read) is never zero.
 */
export function isZeroValue(value: AddressValue | null): boolean {
  return value !== null && value.complete && value.totalUsd === 0 && value.unpriced === 0;
}

async function getJson(url: string, timeoutMs = 12_000): Promise<unknown | null> {
  try {
    await rpcLimiter.acquire();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { headers: { Accept: "application/json" }, signal: controller.signal });
      if (!res.ok) return null;
      return await res.json();
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return null;
  }
}

/** Native coin USD price from the chain's Blockscout stats, then DefiLlama. */
export async function fetchNativePriceUsd(chainId: number): Promise<{ price: number | null; source: string | null }> {
  const host = BLOCKSCOUT_HOSTS[chainId];
  if (host) {
    const stats = (await getJson(`${host}/api/v2/stats`)) as { coin_price?: string } | null;
    const price = stats?.coin_price ? Number(stats.coin_price) : NaN;
    if (Number.isFinite(price) && price > 0) return { price, source: "blockscout" };
  }
  const id = DEFILLAMA_NATIVE_ID[chainId];
  if (id) {
    const d = (await getJson(`https://coins.llama.fi/prices/current/${id}`)) as
      | { coins?: Record<string, { price?: number }> }
      | null;
    const price = d?.coins?.[id]?.price;
    if (typeof price === "number" && Number.isFinite(price)) return { price, source: "defillama" };
  }
  return { price: null, source: null };
}

type BlockscoutTokenBalance = {
  token?: { address_hash?: string; decimals?: string; exchange_rate?: string | null; name?: string; symbol?: string; type?: string };
  value?: string;
};

/** ERC-20 holdings from Blockscout. `ok` false means we could NOT read them. */
export async function fetchBlockscoutTokens(
  chainId: number,
  address: string,
): Promise<{ holdings: TokenHolding[]; ok: boolean; host: string | null }> {
  const host = BLOCKSCOUT_HOSTS[chainId] ?? null;
  if (!host) return { holdings: [], ok: false, host: null };
  const data = await getJson(`${host}/api/v2/addresses/${address}/token-balances`);
  if (!Array.isArray(data)) return { holdings: [], ok: false, host };
  const holdings: TokenHolding[] = [];
  for (const raw of data as BlockscoutTokenBalance[]) {
    const t = raw.token;
    const tokenAddress = t?.address_hash;
    const valueRaw = raw.value;
    if (!tokenAddress || typeof valueRaw !== "string") continue;
    if (t?.type && !/^ERC-20/i.test(t.type)) continue; // skip NFTs / ERC-1155 batches
    const decimals = Number(t?.decimals ?? 18);
    const amount = tokenAmount(valueRaw, Number.isFinite(decimals) ? decimals : 18);
    if (amount === 0) continue; // a zero holding adds nothing
    const rate = t?.exchange_rate ? Number(t.exchange_rate) : NaN;
    const priceUsd = Number.isFinite(rate) && rate > 0 ? rate : null;
    holdings.push({
      kind: "erc20",
      address: tokenAddress.toLowerCase(),
      symbol: t?.symbol ?? "?",
      name: t?.name ?? null,
      decimals: Number.isFinite(decimals) ? decimals : 18,
      raw: valueRaw,
      amount,
      priceUsd,
      valueUsd: usdValue(amount, priceUsd),
      priceSource: priceUsd !== null ? "blockscout" : null,
    });
  }
  return { holdings, ok: true, host };
}

/** DefiLlama prices for `<chain>:<address>` coin keys, batched. */
export async function fetchDefillamaPrices(
  coins: string[],
): Promise<Record<string, { price: number; symbol?: string }>> {
  if (coins.length === 0) return {};
  const out: Record<string, { price: number; symbol?: string }> = {};
  for (let i = 0; i < coins.length; i += 50) {
    const batch = coins.slice(i, i + 50);
    const d = (await getJson(`https://coins.llama.fi/prices/current/${batch.join(",")}`)) as
      | { coins?: Record<string, { price?: number; symbol?: string }> }
      | null;
    for (const [key, v] of Object.entries(d?.coins ?? {})) {
      if (typeof v?.price === "number" && Number.isFinite(v.price)) out[key] = { price: v.price, symbol: v.symbol };
    }
  }
  return out;
}

/**
 * A bounded LRU. The valuation cache MUST NOT grow with the run.
 *
 * It previously was an unbounded Map with a read-time TTL and no eviction, so a
 * 43k-address worker run retained one full AddressValue per address for the
 * whole run — every holding, price, symbol and note — until Node exhausted its
 * ~2GB old space and died ("Reached heap limit Allocation failed"). A TTL only
 * expires an entry if something reads it again; an address that is valued once
 * and never revisited is never reclaimed. Bounding by entry count AND retained
 * bytes is what actually keeps the worker flat.
 */
export class BoundedCache<V> {
  private entries = new Map<string, { value: V; bytes: number }>();
  private retainedBytes = 0;
  // Declared and assigned explicitly rather than as constructor parameter
  // properties: Node's strip-only TypeScript mode (which `npm test` runs under)
  // rejects `constructor(private readonly x: T)` with
  // ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX.
  private readonly maxEntries: number;
  private readonly maxBytes: number;
  private readonly sizeOf: (value: V) => number;
  constructor(maxEntries: number, maxBytes: number, sizeOf: (value: V) => number) {
    this.maxEntries = maxEntries;
    this.maxBytes = maxBytes;
    this.sizeOf = sizeOf;
  }
  get size(): number { return this.entries.size; }
  get bytes(): number { return this.retainedBytes; }
  get(key: string): V | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    // Refresh recency so the LRU order reflects use, not insertion.
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.value;
  }
  set(key: string, value: V): void {
    const bytes = this.sizeOf(value);
    // Never retain something that alone blows the budget.
    if (bytes > this.maxBytes) return;
    const previous = this.entries.get(key);
    if (previous) {
      this.retainedBytes -= previous.bytes;
      this.entries.delete(key);
    }
    this.entries.set(key, { value, bytes });
    this.retainedBytes += bytes;
    while (this.entries.size > this.maxEntries || this.retainedBytes > this.maxBytes) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.retainedBytes -= this.entries.get(oldest)!.bytes;
      this.entries.delete(oldest);
    }
  }
  clear(): void {
    this.entries.clear();
    this.retainedBytes = 0;
  }
}

/** In-memory valuation cache, so a batch values each address once — bounded. */
const CACHE_MAX_ENTRIES = 512;
const CACHE_MAX_BYTES = 8 * 1024 * 1024;
const cache = new BoundedCache<{ at: number; value: AddressValue }>(
  CACHE_MAX_ENTRIES,
  CACHE_MAX_BYTES,
  (entry) => JSON.stringify(entry.value).length,
);
const CACHE_TTL_MS = 5 * 60 * 1000;

export function clearValueCache(): void {
  cache.clear();
}

/** Cache occupancy, for the worker's memory watchdog. */
export function valueCacheStats(): { entries: number; bytes: number } {
  return { entries: cache.size, bytes: cache.bytes };
}

/**
 * Full USD valuation of `address` on `chainId`. Never throws; on provider
 * failure it returns `complete: false` so the caller must not treat the total as
 * authoritative.
 */
export async function fetchAddressValue(
  address: string,
  chain?: number | string | null,
  opts?: { rpcUrls?: string[]; cache?: boolean; maxTokens?: number },
): Promise<AddressValue> {
  const chainId = normalizeChainId(chain);
  const key = `${chainId}:${address.toLowerCase()}`;
  const useCache = opts?.cache !== false;
  if (useCache) {
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.value;
  }

  const symbol = nativeSymbol(chainId);
  const sources: string[] = [];
  const notes: string[] = [];

  // Native balance (RPC) and token balances (Blockscout) in parallel.
  const rpcs = opts?.rpcUrls && opts.rpcUrls.length > 0 ? opts.rpcUrls : rpcUrlsForChain(chainId);
  const [nativeRes, tokenRes, nativePrice] = await Promise.all([
    fetchNativeBalance(address, rpcs, chainId).catch(() => null) as Promise<NativeBalance | null>,
    fetchBlockscoutTokens(chainId, address),
    fetchNativePriceUsd(chainId),
  ]);

  const holdings: TokenHolding[] = [];
  let complete = true;

  // Native coin.
  let nativeWei: string | null = null;
  let nativeUsd: number | null = null;
  if (nativeRes) {
    sources.push("rpc");
    nativeWei = nativeRes.wei.toString();
    const amount = tokenAmount(nativeWei, 18);
    if (nativePrice.price !== null) {
      if (nativePrice.source) sources.push(nativePrice.source);
      nativeUsd = usdValue(amount, nativePrice.price);
      holdings.push({
        kind: "native", address: null, symbol, name: symbol, decimals: 18,
        raw: nativeWei, amount, priceUsd: nativePrice.price, valueUsd: nativeUsd,
        priceSource: nativePrice.source,
      });
    } else {
      // Balance known, price unknown: we cannot value it, so never call it zero.
      complete = false;
      notes.push(`native price unavailable for chain ${chainId}`);
      holdings.push({
        kind: "native", address: null, symbol, name: symbol, decimals: 18,
        raw: nativeWei, amount, priceUsd: null, valueUsd: null, priceSource: null,
      });
    }
  } else {
    complete = false;
    notes.push("native balance unavailable (no RPC answered)");
  }

  // ERC-20 holdings.
  if (tokenRes.ok) {
    if (tokenRes.host) sources.push("blockscout");
    holdings.push(...tokenRes.holdings);
  } else {
    complete = false;
    notes.push(
      tokenRes.host
        ? `token balances unavailable on ${tokenRes.host}`
        : `no token indexer for chain ${chainId}`,
    );
  }

  // Price anything Blockscout left unpriced, via DefiLlama.
  const slug = DEFILLAMA_CHAIN_SLUG[chainId];
  const unpriced = holdings.filter((h) => h.priceUsd === null && h.address !== null);
  if (slug && unpriced.length > 0) {
    const coins = unpriced.map((h) => `${slug}:${h.address}`);
    const prices = await fetchDefillamaPrices(coins);
    if (Object.keys(prices).length > 0) sources.push("defillama");
    for (const h of unpriced) {
      const hit = prices[`${slug}:${h.address}`];
      if (hit) {
        h.priceUsd = hit.price;
        h.valueUsd = usdValue(h.amount, hit.price);
        h.priceSource = "defillama";
      }
    }
  }

  const maxTokens = opts?.maxTokens ?? 200;
  const sorted = holdings.sort((a, b) => (b.valueUsd ?? -1) - (a.valueUsd ?? -1)).slice(0, maxTokens);

  const priced = sorted.filter((h) => h.valueUsd !== null).length;
  const unpricedCount = sorted.filter((h) => h.valueUsd === null).length;
  const totalUsd = totalUsdOf(sorted);

  const value: AddressValue = {
    address,
    chainId,
    symbol,
    nativeWei,
    nativeUsd,
    totalUsd,
    holdings: sorted,
    priced,
    unpriced: unpricedCount,
    sources: Array.from(new Set(sources)),
    // An unpriced holding means the total is a floor, not the truth.
    complete: complete && unpricedCount === 0,
    notes,
    valuedAt: new Date().toISOString(),
  };

  if (useCache) cache.set(key, { at: Date.now(), value });
  return value;
}

/** One-line summary for logs: "$1.23k across 4 holdings (ETH, USDC, …)". */
export function describeValue(value: AddressValue): string {
  const usd = formatUsd(value.totalUsd) ?? "$?";
  const top = value.holdings
    .filter((h) => (h.valueUsd ?? 0) > 0)
    .slice(0, 3)
    .map((h) => h.symbol)
    .join(", ");
  const trust = value.complete ? "" : " (incomplete)";
  return `${usd}${trust} across ${value.holdings.length} holding(s)${top ? ` [${top}]` : ""}`;
}
