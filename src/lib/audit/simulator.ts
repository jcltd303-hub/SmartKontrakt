import { SUPPORTED_CHAINS } from "./address-fetcher";
import { rpcLimiter, withRetry } from "./rate-limit";

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
