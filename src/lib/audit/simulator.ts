import { SUPPORTED_CHAINS } from "./address-fetcher.ts";
import { rpcLimiter, withRetry } from "./rate-limit.ts";
import type { Report } from "./types.ts";

export type CallProbeResult = {
  selector: string;
  name: string;
  success: boolean;
  rawResult?: string;
  decodedString?: string;
  decodedNumber?: string;
  decodedAddress?: string;
  error?: string;
};

const COMMON_PROBES: { name: string; selector: string; returnType: "string" | "uint" | "address" | "bool" }[] = [
  { name: "name()", selector: "0x06fdde03", returnType: "string" },
  { name: "symbol()", selector: "0x95d89b41", returnType: "string" },
  { name: "decimals()", selector: "0x313ce567", returnType: "uint" },
  { name: "totalSupply()", selector: "0x18160ddd", returnType: "uint" },
  { name: "owner()", selector: "0x8da5cb5b", returnType: "address" },
  { name: "paused()", selector: "0x5c975abb", returnType: "bool" },
  { name: "implementation()", selector: "0x5c60da1b", returnType: "address" },
];

function decodeHexWord(hex: string, type: "string" | "uint" | "address" | "bool"): { text?: string; num?: string; addr?: string } {
  if (!hex || hex === "0x") return {};
  const clean = hex.replace(/^0x/, "");

  if (type === "address") {
    if (clean.length >= 40) {
      return { addr: "0x" + clean.slice(-40).toLowerCase() };
    }
  }

  if (type === "uint") {
    try {
      const val = BigInt("0x" + clean.slice(0, 64));
      return { num: val.toString() };
    } catch {
      // ignore
    }
  }

  if (type === "bool") {
    const val = clean.slice(-1) === "1";
    return { text: val ? "true" : "false" };
  }

  if (type === "string") {
    try {
      // Check if it's dynamic ABI string or direct bytes32
      let ascii = "";
      for (let i = 0; i < clean.length; i += 2) {
        const byte = parseInt(clean.substring(i, i + 2), 16);
        if (byte >= 32 && byte <= 126) {
          ascii += String.fromCharCode(byte);
        }
      }
      return { text: ascii.trim() };
    } catch {
      // ignore
    }
  }

  return {};
}

/**
 * Execute public eth_call against target address
 */
export async function executeEthCall(
  address: string,
  calldata: string,
  chainId = "ethereum"
): Promise<{ success: boolean; result?: string; error?: string }> {
  const chain = SUPPORTED_CHAINS.find((c) => c.id === chainId) ?? SUPPORTED_CHAINS[0]!;

  for (const rpcUrl of chain.rpcUrls) {
    try {
      const res = await withRetry(async () => {
        await rpcLimiter.acquire();
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 4000);
        try {
          return await fetch(rpcUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              jsonrpc: "2.0",
              method: "eth_call",
              params: [{ to: address, data: calldata }, "latest"],
              id: 1,
            }),
            signal: controller.signal,
          });
        } finally {
          clearTimeout(timer);
        }
      }, { retries: 1, baseDelayMs: 1500 });
      if (!res.ok) continue;

      const data = (await res.json()) as { result?: string; error?: { message?: string } };
      if (data.error) {
        return { success: false, error: data.error.message || "EVM reverted execution" };
      }

      if (data.result) {
        return { success: true, result: data.result };
      }
    } catch {
      // try next RPC
    }
  }

  return { success: false, error: "RPC nodes unreachable or timed out" };
}

/**
 * Run automatic probe queries on common ERC-20 / Vault / Owner interfaces
 */
export async function probeContractInterfaces(address: string, chainId = "ethereum"): Promise<CallProbeResult[]> {
  const probes = await Promise.all(
    COMMON_PROBES.map(async (probe) => {
      const call = await executeEthCall(address, probe.selector, chainId);
      if (!call.success || !call.result || call.result === "0x") {
        return {
          selector: probe.selector,
          name: probe.name,
          success: false,
          error: call.error || "Reverted / Not implemented",
        };
      }

      const decoded = decodeHexWord(call.result, probe.returnType);
      return {
        selector: probe.selector,
        name: probe.name,
        success: true,
        rawResult: call.result,
        decodedString: decoded.text,
        decodedNumber: decoded.num,
        decodedAddress: decoded.addr,
      };
    })
  );

  return probes;
}

/**
 * Latest block number on the chain, or null when no RPC answers.
 * Same rotation / limiter / retry discipline as executeEthCall — the
 * live-state probes (live-state.ts) stamp their report with it so a
 * reader knows exactly which chain height the values were read at.
 */
export async function fetchLatestBlockNumber(chainId = "ethereum"): Promise<number | null> {
  const chain = SUPPORTED_CHAINS.find((c) => c.id === chainId) ?? SUPPORTED_CHAINS[0]!;

  for (const rpcUrl of chain.rpcUrls) {
    try {
      const res = await withRetry(async () => {
        await rpcLimiter.acquire();
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 4000);
        try {
          return await fetch(rpcUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              jsonrpc: "2.0",
              method: "eth_blockNumber",
              params: [],
              id: 1,
            }),
            signal: controller.signal,
          });
        } finally {
          clearTimeout(timer);
        }
      }, { retries: 1, baseDelayMs: 1500 });
      if (!res.ok) continue;

      const data = (await res.json()) as { result?: string };
      if (typeof data.result === "string") {
        const n = parseInt(data.result, 16);
        if (Number.isFinite(n)) return n;
      }
    } catch {
      // try next RPC
    }
  }

  return null;
}

/**
 * The on-chain name() probe value, sanitized (Item 1). Returns null when
 * the probe did not succeed, returned nothing printable, or returned
 * something that is not a name (an address, a >120-char blob, control
 * characters). A rejected probe name falls through to the analyzed
 * contract name — never shown raw.
 */
export function probeOnChainName(probes: CallProbeResult[] | null | undefined): string | null {
  const hit = probes?.find((p) => p.name === "name()" && p.success);
  const s = hit?.decodedString?.trim() ?? "";
  if (!s || s.length > 120) return null;
  if (/[^\x20-\x7e]/.test(s)) return null;
  if (/^0x[0-9a-fA-F]{40}$/.test(s)) return null;
  return s;
}

/**
 * THE record display-name rule (Item 1), shared by every surface that
 * names a record: worker bulk save, workbench single save, RAG chunks,
 * and the workbench header. Order:
 *   1. On-chain name() probe value (what the deployed contract calls
 *      itself — "The Baller Bananas", "My Rug NFT").
 *   2. The analyzed/main contract's name (Item 2 selection: the
 *      deployed contract, not the first file in the source).
 *   3. First contract in the file (previous behavior, last resort).
 *   4. The record label (CSV / file / paste label).
 * Old records keep whatever contract_name they were saved with — this
 * rule applies at save/render time going forward, with no backfill.
 */
export function resolveContractDisplayName(
  probes: CallProbeResult[] | null | undefined,
  report: Report,
): string {
  return (
    probeOnChainName(probes) ??
    report.mainContract ??
    report.inventory.contractNames[0] ??
    report.label
  );
}
