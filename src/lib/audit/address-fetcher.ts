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
 * Parses multiline text (one address per line, with optional comments or labels)
 * Example input:
 *   0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984 # UNI Token
 *   0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D, UniswapV2Router
 */
export function parseAddressList(text: string, defaultChainId = "ethereum"): BatchItem[] {
  const lines = text.split(/\r?\n/);
  const items: BatchItem[] = [];
  const seen = new Set<string>();

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i]?.trim() ?? "";
    if (!rawLine || rawLine.startsWith("//") || rawLine.startsWith("#")) continue;

    // Check for address pattern
    const match = rawLine.match(/(0x[0-9a-fA-F]{40})/);
    if (!match || !match[1]) continue;

    const address = match[1].toLowerCase();
    if (seen.has(address)) continue;
    seen.add(address);

    // Try to extract an optional label after delimiter (#, ,, :)
    let label = "";
    const afterAddress = rawLine.replace(match[1], "").trim();
    if (afterAddress) {
      label = afterAddress.replace(/^[#,:\-\s]+/, "").trim();
    }
    if (!label) {
      label = `Contract ${address.slice(0, 6)}...${address.slice(-4)}`;
    }

    items.push({
      id: `addr-${address}-${i}`,
      address,
      label,
      chainId: defaultChainId,
      status: "pending",
    });
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
