/**
 * Native-coin balance of a contract, read over public JSON-RPC.
 *
 * Used for two things:
 *  - the scan record (the balance at analysis time), and
 *  - the pre-run guard: a fork PoC against a target holding no native value has
 *    nothing at stake, so it is skipped rather than run.
 *
 * Dependency-light on purpose — imported by both the browser pipeline and the
 * headless worker.
 */
import { rpcLimiter } from "./rate-limit.ts";

export type NativeBalance = {
  /** Balance in wei. */
  wei: bigint;
  /** Human decimal string, e.g. "1.234567". */
  formatted: string;
  /** Native symbol for the chain (ETH / POL / BNB). */
  symbol: string;
  /** The RPC that answered. */
  rpcUrl: string;
};

const NATIVE_SYMBOL: Record<number, string> = {
  1: "ETH",
  42161: "ETH",
  10: "ETH",
  8453: "ETH",
  137: "POL",
  56: "BNB",
};

const CHAIN_ID_BY_NAME: Record<string, number> = {
  ethereum: 1, arbitrum: 42161, base: 8453, optimism: 10, polygon: 137, bsc: 56,
};

/** Chain id from a numeric or named chain reference. */
export function normalizeChainId(chain?: number | string | null): number {
  if (chain === undefined || chain === null || chain === "") return 1;
  if (typeof chain === "number") return chain;
  const byName = CHAIN_ID_BY_NAME[chain.toLowerCase()];
  if (byName !== undefined) return byName;
  const n = Number(chain);
  return Number.isFinite(n) ? n : 1;
}

/** Native coin symbol for a chain (defaults to ETH). */
export function nativeSymbol(chain?: number | string | null): string {
  return NATIVE_SYMBOL[normalizeChainId(chain)] ?? "ETH";
}

/**
 * Format wei as a short decimal string (18 decimals, ≤6 shown, trailing zeros
 * trimmed). Dust below 6 dp renders as "<0.000001" rather than "0.000000", so a
 * non-zero balance is never displayed — or styled — as zero.
 */
export function formatNative(wei: bigint, decimals = 18): string {
  if (wei === 0n) return "0";
  const base = 10n ** BigInt(decimals);
  const whole = wei / base;
  const frac = wei % base;
  if (frac === 0n) return whole.toString();
  const fracStr = frac.toString().padStart(decimals, "0").slice(0, 6).replace(/0+$/, "");
  if (!fracStr) return whole === 0n ? "<0.000001" : whole.toString();
  return `${whole}.${fracStr}`;
}

/** Parse a JSON-RPC hex quantity into wei; null when malformed. */
export function weiFromHex(hex: unknown): bigint | null {
  if (typeof hex !== "string" || !/^0x[0-9a-fA-F]+$/.test(hex)) return null;
  try {
    return BigInt(hex);
  } catch {
    return null;
  }
}

/**
 * Read the native balance via `eth_getBalance` over the given RPCs. Returns the
 * first usable answer, or null when every endpoint fails (an outage is NOT a
 * zero balance — callers must not treat null as "empty").
 */
export async function fetchNativeBalance(
  address: string,
  rpcUrls: string[],
  chain?: number | string | null,
): Promise<NativeBalance | null> {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) return null;
  for (const rpcUrl of rpcUrls) {
    try {
      await rpcLimiter.acquire();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      let res: Response;
      try {
        res = await fetch(rpcUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            method: "eth_getBalance",
            params: [address, "latest"],
            id: 1,
          }),
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timer);
      }
      if (!res.ok) continue;
      const json = (await res.json()) as { result?: unknown };
      const wei = weiFromHex(json.result);
      if (wei !== null) {
        return { wei, formatted: formatNative(wei), symbol: nativeSymbol(chain), rpcUrl };
      }
    } catch {
      // try the next RPC
    }
  }
  return null;
}

/** True only for a CONFIRMED zero balance (null / unknown is not zero). */
export function isZeroBalance(balance: NativeBalance | null): boolean {
  return balance !== null && balance.wei === 0n;
}

/**
 * Display string for a stored balance ("1.234567 ETH"), or null when unknown.
 * Never throws on malformed input.
 */
export function balanceLabel(
  wei: string | bigint | null | undefined,
  symbol = "ETH",
): string | null {
  if (wei === null || wei === undefined || wei === "") return null;
  try {
    const value = typeof wei === "bigint" ? wei : BigInt(wei);
    return `${formatNative(value)} ${symbol}`;
  } catch {
    return null;
  }
}
