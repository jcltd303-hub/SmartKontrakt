import type { Report } from "./types";
import { analyzeInput } from "./engine";

export type SupportedChain = {
  id: string;
  name: string;
  chainId: number;
  rpcUrls: string[];
  blockExplorer: string;
};

export const SUPPORTED_CHAINS: SupportedChain[] = [
  {
    id: "ethereum",
    name: "Ethereum Mainnet",
    chainId: 1,
    rpcUrls: ["https://cloudflare-eth.com", "https://eth.llamarpc.com"],
    blockExplorer: "https://etherscan.io",
  },
  {
    id: "arbitrum",
    name: "Arbitrum One",
    chainId: 42161,
    rpcUrls: ["https://arb1.arbitrum.io/rpc", "https://arbitrum.llamarpc.com"],
    blockExplorer: "https://arbiscan.io",
  },
  {
    id: "base",
    name: "Base",
    chainId: 8453,
    rpcUrls: ["https://mainnet.base.org", "https://base.llamarpc.com"],
    blockExplorer: "https://basescan.org",
  },
  {
    id: "optimism",
    name: "Optimism",
    chainId: 10,
    rpcUrls: ["https://mainnet.optimism.io"],
    blockExplorer: "https://optimistic.etherscan.io",
  },
  {
    id: "polygon",
    name: "Polygon",
    chainId: 137,
    rpcUrls: ["https://polygon-rpc.com"],
    blockExplorer: "https://polygonscan.com",
  },
  {
    id: "bsc",
    name: "BNB Smart Chain",
    chainId: 56,
    rpcUrls: ["https://bsc-dataseed.binance.org"],
    blockExplorer: "https://bscscan.com",
  },
];

export type BatchItemStatus = "pending" | "fetching" | "analyzing" | "completed" | "failed" | "skipped";

export type BatchItem = {
  id: string;
  address: string;
  label: string;
  chainId: string;
  status: BatchItemStatus;
  inputKind?: "source" | "bytecode";
  rawBody?: string;
  error?: string;
  bytecodeSize?: number;
  riskScore?: number;
  findingsCount?: number;
  criticalCount?: number;
  highCount?: number;
  report?: Report;
  completedAt?: string;
};

/**
 * Validates if a string matches standard EVM 20-byte hex address
 */
export function isValidEvmAddress(address: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(address.trim());
}

/**
 * High-performance, zero-allocation line scanner to count valid EVM addresses
 * without creating intermediate string arrays or BatchItem objects.
 */
export function countValidAddresses(text: string): number {
  if (!text) return 0;
  let count = 0;
  const seen = new Set<string>();
  const len = text.length;
  let start = 0;

  while (start < len) {
    let end = text.indexOf("\n", start);
    if (end === -1) end = len;

    if (end - start >= 42) {
      const hexOffset = text.indexOf("0x", start);
      if (hexOffset !== -1 && hexOffset + 42 <= end) {
        const cand = text.slice(hexOffset, hexOffset + 42);
        if (isValidEvmAddress(cand)) {
          const lower = cand.toLowerCase();
          if (!seen.has(lower)) {
            seen.add(lower);
            count++;
          }
        }
      }
    }

    start = end + 1;
  }

  return count;
}

/**
 * High-performance parser for large address lists (e.g. 50,000+ contracts).
 * Uses index-based streaming line scanning rather than text.split to avoid
 * memory spikes, garbage collection pauses, and temporary string arrays.
 */
export function parseAddressList(
  text: string,
  defaultChainId = "ethereum",
  maxLimit = 100_000
): BatchItem[] {
  if (!text) return [];
  const items: BatchItem[] = [];
  const seen = new Set<string>();
  const len = text.length;

  let start = 0;
  let lineIdx = 0;

  while (start < len && items.length < maxLimit) {
    let end = text.indexOf("\n", start);
    if (end === -1) end = len;

    const lineLen = end - start;
    if (lineLen >= 42) {
      const hexOffset = text.indexOf("0x", start);
      if (hexOffset !== -1 && hexOffset + 42 <= end) {
        const addrCandidate = text.slice(hexOffset, hexOffset + 42);
        if (isValidEvmAddress(addrCandidate)) {
          const lowerAddr = addrCandidate.toLowerCase();
          if (!seen.has(lowerAddr)) {
            seen.add(lowerAddr);

            // Extract optional label from remainder of line
            let label = "";
            const before = text.slice(start, hexOffset).trim();
            const after = text.slice(hexOffset + 42, end).trim();
            const remainder = (before ? before + " " : "") + after;
            if (remainder) {
              const cleaned = remainder.replace(/^[#,:\-\s]+/, "").trim();
              if (cleaned && !cleaned.startsWith("//")) {
                label = cleaned.slice(0, 60);
              }
            }
            if (!label) {
              label = `Contract ${lowerAddr.slice(0, 6)}...${lowerAddr.slice(-4)}`;
            }

            items.push({
              id: `addr-${lowerAddr}-${lineIdx}`,
              address: lowerAddr,
              label,
              chainId: defaultChainId,
              status: "pending",
            });
          }
        }
      }
    }

    start = end + 1;
    lineIdx++;
  }

  return items;
}

/**
 * Fetch verified source code from Sourcify public API
 */
async function fetchSourcifySource(address: string, chainIdNumber: number): Promise<{ source: string; name: string } | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    const url = `https://sourcify.dev/server/files/any/${chainIdNumber}/${address}`;
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) return null;

    const data = (await res.json()) as { files?: { name: string; content: string }[] };
    if (!data || !Array.isArray(data.files) || data.files.length === 0) return null;

    // Look for solidity files
    const solFiles = data.files.filter((f) => f.name.endsWith(".sol"));
    if (solFiles.length === 0) return null;

    // Combine or pick primary
    const mainFile = solFiles.find((f) => !f.name.includes("/") && !f.name.toLowerCase().includes("interface")) ?? solFiles[0];
    const source = solFiles.length === 1 || !mainFile
      ? solFiles.map((f) => `// File: ${f.name}\n${f.content}`).join("\n\n")
      : mainFile.content;

    const name = mainFile?.name.replace(/\.sol$/, "") ?? "VerifiedContract";
    return { source, name };
  } catch {
    return null;
  }
}

/**
 * Fetch deployed runtime bytecode via eth_getCode over public EVM JSON-RPC
 */
async function fetchBytecodeRpc(address: string, rpcUrls: string[]): Promise<string | null> {
  for (const rpcUrl of rpcUrls) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);

      const res = await fetch(rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "eth_getCode",
          params: [address, "latest"],
          id: 1,
        }),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!res.ok) continue;
      const json = (await res.json()) as { result?: string; error?: unknown };
      const code = json.result;

      if (code && typeof code === "string" && code !== "0x" && code.length > 4) {
        return code;
      }
    } catch {
      // try next RPC
    }
  }

  return null;
}

/**
 * Pipeline processor for a single EVM address:
 * 1. Queries Sourcify for verified Solidity source code
 * 2. If not found, queries public RPC for runtime bytecode
 * 3. Runs Kiln static AST & bytecode analyzer
 */
export async function analyzeAddress(
  address: string,
  chainId = "ethereum",
  customLabel?: string
): Promise<{ report: Report; rawBody: string; inputKind: "source" | "bytecode" }> {
  if (!isValidEvmAddress(address)) {
    throw new Error(`Invalid EVM address format: ${address}`);
  }

  const chain = SUPPORTED_CHAINS.find((c) => c.id === chainId) ?? SUPPORTED_CHAINS[0]!;

  // 1. Try Sourcify verified source
  const sourcifyMatch = await fetchSourcifySource(address, chain.chainId);
  if (sourcifyMatch) {
    const label = customLabel || sourcifyMatch.name || `Verified (${address.slice(0, 6)}...)`;
    const report = analyzeInput(sourcifyMatch.source, label);
    return {
      report,
      rawBody: sourcifyMatch.source,
      inputKind: "source",
    };
  }

  // 2. Fetch runtime bytecode via eth_getCode
  const bytecode = await fetchBytecodeRpc(address, chain.rpcUrls);
  if (!bytecode) {
    throw new Error(`No deployed bytecode found at ${address} on ${chain.name}. It may be an un-deployed EOA or destroyed contract.`);
  }

  const label = customLabel || `Bytecode (${address.slice(0, 6)}...${address.slice(-4)})`;
  const report = analyzeInput(bytecode, label);

  return {
    report,
    rawBody: bytecode,
    inputKind: "bytecode",
  };
}
