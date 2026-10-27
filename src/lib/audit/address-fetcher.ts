import { sha3_256 } from "js-sha3";
import type { Report } from "./types.ts";
import { analyzeInput } from "./engine.ts";
import { analyzeBytecode } from "./bytecode.ts";
import { rpcLimiter, sourcifyLimiter, blockscoutLimiter, withRetry } from "./rate-limit.ts";
import { fetchAddressValue } from "./value.ts";
import { gatherAbi } from "./abi.ts";
import { gatherLiveState } from "./live-state.ts";
import { applyInitializerGate } from "./initializer-gate.ts";
import { enrichReportFourbyte, type FourbyteLookup } from "./fourbyte.ts";
import { attachResnetToReport, runtimeCodeForReport, type ResnetRunner } from "./resnet-attach.ts";

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
    rpcUrls: [
      // Verified 2026-10-16: Cloudflare-eth returns JSON-RPC -32603
      // "Internal error" for every request and Llama returns HTTP 525,
      // so the working public endpoints go first. Ankr is excluded:
      // it now requires an API key.
      "https://ethereum.publicnode.com",
      "https://eth.drpc.org",
      "https://1rpc.io/eth",
      "https://cloudflare-eth.com",
      "https://eth.llamarpc.com",
    ],
    blockExplorer: "https://etherscan.io",
  },
  {
    id: "arbitrum",
    name: "Arbitrum One",
    chainId: 42161,
    rpcUrls: [
      "https://arb1.arbitrum.io/rpc",
      "https://arbitrum.llamarpc.com",
      "https://arbitrum-one.publicnode.com",
      "https://1rpc.io/arb",
    ],
    blockExplorer: "https://arbiscan.io",
  },
  {
    id: "base",
    name: "Base",
    chainId: 8453,
    rpcUrls: [
      "https://mainnet.base.org",
      "https://base.llamarpc.com",
      "https://base.publicnode.com",
      "https://1rpc.io/base",
    ],
    blockExplorer: "https://basescan.org",
  },
  {
    id: "optimism",
    name: "Optimism",
    chainId: 10,
    rpcUrls: [
      "https://mainnet.optimism.io",
      "https://optimism.publicnode.com",
      "https://1rpc.io/op",
    ],
    blockExplorer: "https://optimistic.etherscan.io",
  },
  {
    id: "polygon",
    name: "Polygon",
    chainId: 137,
    rpcUrls: [
      "https://polygon-rpc.com",
      "https://polygon-bor-rpc.publicnode.com",
      "https://1rpc.io/matic",
    ],
    blockExplorer: "https://polygonscan.com",
  },
  {
    id: "bsc",
    name: "BNB Smart Chain",
    chainId: 56,
    rpcUrls: [
      "https://bsc-dataseed.binance.org",
      "https://bsc.publicnode.com",
      "https://1rpc.io/bnb",
    ],
    blockExplorer: "https://bscscan.com",
  },
];

export const ALL_RPC_URLS: string[] = Array.from(
  new Set(SUPPORTED_CHAINS.flatMap((c) => c.rpcUrls))
);

/**
 * Resolve a user-supplied chain reference — a canonical id ("ethereum"),
 * a case variant ("Ethereum"), a display name ("BNB Smart Chain"), or a
 * numeric chain id ("1", "56") — to the canonical SUPPORTED_CHAINS id.
 * Unknown values pass through trimmed: a chain this build does not know
 * keeps its caller-supplied spelling rather than being silently remapped.
 *
 * Every (chain, address) key in the system — the saved-scan skip check,
 * the in-run dedupe set, the chain_id written on save — is built from
 * the chain id, so a non-canonical spelling ("Ethereum", "1") would
 * never match the stored "ethereum" rows: the entry would re-analyze
 * forever and save under a divergent chain_id. Canonicalizing at parse
 * time (the one place file items are born) keeps every key downstream
 * in the canonical spelling.
 */
export function canonicalChainId(raw?: string | null): string {
  const needle = (raw ?? "").trim();
  if (!needle) return "ethereum";
  const lower = needle.toLowerCase();
  const match = SUPPORTED_CHAINS.find(
    (c) => c.id.toLowerCase() === lower || c.name.toLowerCase().includes(lower) || String(c.chainId) === needle
  );
  return match ? match.id : needle;
}

export function getRpcsForChain(chainIdOrName?: string): string[] {
  if (!chainIdOrName) return SUPPORTED_CHAINS[0].rpcUrls;
  const needle = chainIdOrName.toLowerCase().trim();
  const match = SUPPORTED_CHAINS.find(
    (c) => c.id.toLowerCase() === needle || c.name.toLowerCase().includes(needle) || String(c.chainId) === needle
  );
  return match ? match.rpcUrls : SUPPORTED_CHAINS[0].rpcUrls;
}

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
  /** Native balance (wei, decimal string) at analysis time (migration 0011). */
  balanceWei?: string | null;
  /** Total USD value at analysis time (migration 0012). */
  valueUsd?: number | null;
  findingsCount?: number;
  criticalCount?: number;
  highCount?: number;
  report?: Report;
  completedAt?: string;
  scanId?: string;
  persisted?: boolean;
  supabaseSynced?: boolean;
  summary?: string;
};

/**
 * Validates if a string matches standard EVM 20-byte hex address
 */
export function isValidEvmAddress(address: string): boolean {
  if (!address) return false;
  const clean = address.trim();
  return /^0x[0-9a-fA-F]{40}$/i.test(clean);
}

/**
 * Extracts the EVM contract address from the first column of a CSV or multiline text row.
 * Handles:
 * - CSV files with quotes: "0x123...","Contract Name",...
 * - CSV files without quotes: 0x123...,Contract Name,...
 * - Semicolon and tab delimited formats
 * - Excel CSV files with UTF-8 BOM (\uFEFF)
 * - Single address per line: 0x123...
 * - Addresses with comments or labels: 0x123... # Uniswap Token
 * Skips CSV headers, comments, empty lines, and lines where the first column is not an EVM address.
 */
export function extractFirstColAddress(line: string): { address: string; label?: string; chainIdHint?: string } | null {
  let trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("//")) return null;
  if (trimmed.charCodeAt(0) === 0xfeff) trimmed = trimmed.slice(1).trim();

  let col1 = "";
  let col2 = "";
  let col3 = "";

  if (trimmed.charCodeAt(0) === 34 || trimmed.charCodeAt(0) === 39) {
    // Quoted first column: e.g. "0x...", "label"
    const q = trimmed.charAt(0);
    let i = 1;
    while (i < trimmed.length) {
      if (trimmed.charAt(i) === q) {
        if (i + 1 < trimmed.length && trimmed.charAt(i + 1) === q) {
          col1 += q;
          i += 2;
          continue;
        }
        break;
      }
      col1 += trimmed.charAt(i);
      i++;
    }

    let remainder = trimmed.slice(i + 1).trim();
    if (remainder.startsWith(",") || remainder.startsWith(";") || remainder.startsWith("\t")) {
      remainder = remainder.slice(1).trim();
    }

    if (remainder) {
      if (remainder.charCodeAt(0) === 34 || remainder.charCodeAt(0) === 39) {
        const q2 = remainder.charAt(0);
        let j = 1;
        while (j < remainder.length) {
          if (remainder.charAt(j) === q2) {
            if (j + 1 < remainder.length && remainder.charAt(j + 1) === q2) {
              col2 += q2;
              j += 2;
              continue;
            }
            break;
          }
          col2 += remainder.charAt(j);
          j++;
        }
        const rem2 = remainder.slice(j + 1).trim();
        if (rem2.startsWith(",") || rem2.startsWith(";")) {
          col3 = rem2.slice(1).trim().replace(/^["']|["']$/g, "");
        }
      } else {
        const delim = remainder.search(/[,;\t]/);
        if (delim !== -1) {
          col2 = remainder.slice(0, delim).trim();
          col3 = remainder.slice(delim + 1).trim().replace(/^["']|["']$/g, "");
        } else {
          col2 = remainder;
        }
      }
    }
  } else {
    // Unquoted first column: check for delimiter (comma, semicolon, tab)
    const delimMatch = trimmed.match(/[,;\t]/);
    if (delimMatch && delimMatch.index !== undefined) {
      const idx = delimMatch.index;
      col1 = trimmed.slice(0, idx).trim().replace(/^["']|["']$/g, "");
      const remainder = trimmed.slice(idx + 1).trim();

      if (remainder) {
        if (remainder.charCodeAt(0) === 34 || remainder.charCodeAt(0) === 39) {
          const q2 = remainder.charAt(0);
          let j = 1;
          while (j < remainder.length) {
            if (remainder.charAt(j) === q2) {
              if (j + 1 < remainder.length && remainder.charAt(j + 1) === q2) {
                col2 += q2;
                j += 2;
                continue;
              }
              break;
            }
            col2 += remainder.charAt(j);
            j++;
          }
          const rem2 = remainder.slice(j + 1).trim();
          if (rem2.startsWith(",") || rem2.startsWith(";")) {
            col3 = rem2.slice(1).trim().replace(/^["']|["']$/g, "");
          }
        } else {
          const delim2 = remainder.search(/[,;\t]/);
          if (delim2 !== -1) {
            col2 = remainder.slice(0, delim2).trim();
            col3 = remainder.slice(delim2 + 1).trim().replace(/^["']|["']$/g, "");
          } else {
            col2 = remainder;
          }
        }
      }
    } else {
      // Space or hash separation (e.g. "0x123... # Uniswap" or "0x123... Uniswap")
      const sepMatch = trimmed.match(/[\s#]/);
      if (sepMatch && sepMatch.index !== undefined) {
        col1 = trimmed.slice(0, sepMatch.index).trim().replace(/^["']|["']$/g, "");
        col2 = trimmed.slice(sepMatch.index).trim().replace(/^[#:\-\s]+/, "").trim();
      } else {
        col1 = trimmed.replace(/^["']|["']$/g, "");
      }
    }
  }

  // Clean and validate address in first column
  let cleanAddr = col1.trim();
  if (cleanAddr.charCodeAt(0) === 0xfeff) cleanAddr = cleanAddr.slice(1).trim();
  if (cleanAddr.startsWith("ethereum:")) cleanAddr = cleanAddr.slice(9);
  if (!isValidEvmAddress(cleanAddr)) return null;

  // Clean label from second column
  let label = col2.trim().replace(/^["']|["']$/g, "").trim();
  if (label && (label.startsWith("//") || label.startsWith("#"))) {
    label = label.replace(/^[#/\-\s]+/, "").trim();
  }
  // If label is purely numeric (e.g. balance or id like 100000000), omit it so default format is used
  if (/^\d+(\.\d+)?$/.test(label)) {
    label = "";
  }

  // Optional Chain ID hint from column 3
  let chainIdHint: string | undefined;
  if (col3) {
    const c3 = col3.trim().toLowerCase();
    const match = SUPPORTED_CHAINS.find(
      (c) => c.id === c3 || c.chainId.toString() === c3 || c.name.toLowerCase().includes(c3)
    );
    if (match) chainIdHint = match.id;
  }

  return {
    address: cleanAddr.toLowerCase(),
    label: label ? label.slice(0, 60) : undefined,
    chainIdHint,
  };
}

/**
 * High-performance, zero-allocation line scanner to count valid EVM addresses
 * in the first column of CSV or multiline text.
 */
export function countValidAddresses(text: string, defaultChainId = "ethereum"): number {
  if (!text) return 0;
  let count = 0;
  const seen = new Set<string>();
  const len = text.length;
  let start = 0;

  while (start < len) {
    let end = text.indexOf("\n", start);
    if (end === -1) end = len;

    const line = text.slice(start, end);
    const parsed = extractFirstColAddress(line);
    // Dedupe key is (chain, address), exactly as parseAddressList builds
    // items: the same address on two chains is two entries, not a dupe.
    const key = parsed ? `${parsed.chainIdHint || canonicalChainId(defaultChainId)}:${parsed.address}` : null;
    if (parsed && key && !seen.has(key)) {
      seen.add(key);
      count++;
    }

    start = end + 1;
  }

  return count;
}

/**
 * High-performance parser for large address lists and CSV files (e.g. 50,000+ contracts).
 * Accurately extracts the EVM address from the FIRST column of each CSV row,
 * optionally pulling the contract label from column 2 and network from column 3.
 * Skips CSV headers, non-address rows, and duplicates.
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

    const line = text.slice(start, end);
    const parsed = extractFirstColAddress(line);
    // Dedupe key is (chain, address): the same address listed for two
    // chains is two entries (its scans, saves and skip keys are all
    // chain-scoped), while a true duplicate — same chain, any address
    // case — collapses to the first occurrence. Keying on the address
    // alone silently dropped the second chain's entry.
    const chainId = parsed ? parsed.chainIdHint || canonicalChainId(defaultChainId) : null;
    const dedupeKey = parsed && chainId ? `${chainId}:${parsed.address}` : null;
    if (parsed && chainId && dedupeKey && !seen.has(dedupeKey)) {
      seen.add(dedupeKey);
      const lowerAddr = parsed.address;
      const label = parsed.label || `Contract ${lowerAddr.slice(0, 6)}...${lowerAddr.slice(-4)}`;

      items.push({
        id: `addr-${lowerAddr}-${lineIdx}`,
        address: lowerAddr,
        label,
        chainId,
        status: "pending",
      });
    }

    start = end + 1;
    lineIdx++;
  }

  return items;
}

/**
 * Where a verified source came from. C1 (2026-10-27 detection upgrade): a
 * single-source fetcher (Sourcify only) declared 19 of 21 "unverified"
 * contracts unanalysable when they were verified on a second registry —
 * 1,160 ETH of coverage lost to one missing fallback. Every match now
 * carries its registry so the record says where the source came from.
 */
export type VerifiedSourceMatch = {
  source: string;
  name: string;
  contractName: string | null;
  registry: "sourcify" | "blockscout";
};

/**
 * Blockscout hosts, by chain. Blockscout runs a per-chain instance and its
 * v2 API needs no key, which is what makes it usable from the browser as
 * well as the worker. Chains without a public instance simply fall through
 * to the bytecode path (and are labelled as analysed, never unreadable).
 */
export const BLOCKSCOUT_HOSTS: Record<number, string> = {
  1: "https://eth.blockscout.com",
  10: "https://optimism.blockscout.com",
  100: "https://gnosis.blockscout.com",
  137: "https://polygon.blockscout.com",
  8453: "https://base.blockscout.com",
  42161: "https://arbitrum.blockscout.com",
};

export function blockscoutHost(chainIdNumber: number): string | null {
  return BLOCKSCOUT_HOSTS[chainIdNumber] ?? null;
}

/** `/api/v2/smart-contracts/{address}` — the verified-source endpoint. */
export function blockscoutContractUrl(host: string, address: string): string {
  return `${host.replace(/\/+$/, "")}/api/v2/smart-contracts/${address.toLowerCase()}`;
}

/** `/api/v2/addresses/{address}` — identity + creation bytecode, served even
 *  when `is_verified` is false (C2). */
export function blockscoutAddressUrl(host: string, address: string): string {
  return `${host.replace(/\/+$/, "")}/api/v2/addresses/${address.toLowerCase()}`;
}

type BlockscoutContract = {
  is_verified?: boolean;
  name?: string | null;
  source_code?: string | null;
  abi?: unknown;
  compiler_version?: string | null;
  is_proxy?: boolean | null;
};

type BlockscoutAddress = {
  is_contract?: boolean | null;
  name?: string | null;
  is_verified?: boolean | null;
  creation_bytecode?: string | null;
  deployed_bytecode?: string | null;
  implementations?: { address?: string; name?: string | null }[] | null;
  proxy_type?: string | null;
};

async function blockscoutJson<T>(url: string): Promise<T | null> {
  try {
    const res = await withRetry(async () => {
      await blockscoutLimiter.acquire();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4000);
      try {
        return await fetch(url, { signal: controller.signal, headers: { accept: "application/json" } });
      } finally {
        clearTimeout(timer);
      }
    }, { retries: 2, baseDelayMs: 1000 });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

/**
 * Fetch verified source from Blockscout (the C1 second registry). Returns
 * null for an unverified contract — "no source" is a fact about the
 * registry, not about the address: the caller still has the creation
 * bytecode route below.
 */
export async function fetchBlockscoutSource(address: string, chainIdNumber: number): Promise<VerifiedSourceMatch | null> {
  const host = blockscoutHost(chainIdNumber);
  if (!host) return null;
  const data = await blockscoutJson<BlockscoutContract>(blockscoutContractUrl(host, address));
  if (!data) return null;
  const source = typeof data.source_code === "string" ? data.source_code.trim() : "";
  if (!source) return null;
  const name = (data.name ?? "").trim() || `Verified (${address.slice(0, 6)}...)`;
  return {
    source,
    name,
    contractName: data.is_verified === false ? null : name,
    registry: "blockscout",
  };
}

export type BlockscoutIdentity = {
  name: string | null;
  isContract: boolean | null;
  isVerified: boolean | null;
  hasCreationBytecode: boolean;
  implementations: string[];
  proxyType: string | null;
};

/**
 * Identity for an address whose source no registry returned (C2/C3).
 * Blockscout serves this for unverified contracts too, which is how a
 * "no source" address still gets a real name, a proxy shape and a
 * creation-bytecode route instead of the label "unreadable".
 */
export async function fetchBlockscoutIdentity(address: string, chainIdNumber: number): Promise<BlockscoutIdentity | null> {
  const host = blockscoutHost(chainIdNumber);
  if (!host) return null;
  const data = await blockscoutJson<BlockscoutAddress>(blockscoutAddressUrl(host, address));
  if (!data) return null;
  const impls = Array.isArray(data.implementations)
    ? data.implementations.map((i) => i?.address ?? "").filter(Boolean)
    : [];
  return {
    name: (data.name ?? "").trim() || null,
    isContract: data.is_contract ?? null,
    isVerified: data.is_verified ?? null,
    hasCreationBytecode: typeof data.creation_bytecode === "string" && data.creation_bytecode.length > 2,
    implementations: impls,
    proxyType: data.proxy_type ?? null,
  };
}

/**
 * The label a bytecode-only audit gets. "Bytecode-analysed", never
 * "unreadable": the runtime was disassembled, its selectors extracted and
 * its shape classified, so the address was analysed — just not from
 * source. Phase 2's target is that no address is reported as unanalysable
 * because one registry had nothing.
 */
export function bytecodeAnalysedLabel(address: string, identity?: BlockscoutIdentity | null): string {
  const short = `${address.slice(0, 6)}...${address.slice(-4)}`;
  const name = identity?.name ? `${identity.name} · ` : "";
  return `Bytecode-analysed (${name}${short})`;
}

/** The note that explains what a bytecode-only audit did and did not cover. */
export function bytecodeAnalysedNote(identity?: BlockscoutIdentity | null): string {
  const parts = [
    "No registry returned verified source (Sourcify, then Blockscout), so this audit is of the runtime bytecode: opcodes, selectors and proxy shape are ground truth, source-level semantics are inferred.",
  ];
  if (identity?.hasCreationBytecode) {
    parts.push("Blockscout served the creation bytecode, so constructor-time state is inspectable even though the source is unpublished.");
  }
  if (identity?.proxyType) {
    parts.push(`Blockscout reports proxy type ${identity.proxyType}${identity.implementations.length ? ` with implementation ${identity.implementations.join(", ")}` : ""}.`);
  }
  if (identity?.name) {
    parts.push(`Blockscout's name for the address is "${identity.name}" — registry metadata, not a compiler-verified label.`);
  }
  return parts.join(" ");
}

/**
 * Fetch verified source code from Sourcify public API
 */
async function fetchSourcifySource(address: string, chainIdNumber: number): Promise<VerifiedSourceMatch | null> {
  try {
    const url = `https://sourcify.dev/server/files/any/${chainIdNumber}/${address}`;
    const res = await withRetry(async () => {
      await sourcifyLimiter.acquire();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4000);
      try {
        return await fetch(url, { signal: controller.signal });
      } finally {
        clearTimeout(timer);
      }
    }, { retries: 2, baseDelayMs: 1000 });
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
    // Scope detection to the deployed contract only when the match is a
    // single file: the filename (Deed.sol) names the deployed contract
    // (Deed). For multi-file matches the filename is a dependency as often
    // as the main contract, so no scoping — detectSource falls back to all
    // contracts when the name matches nothing.
    const contractName = solFiles.length === 1 ? name : null;
    return { source, name, contractName, registry: "sourcify" as const };
  } catch {
    return null;
  }
}

/**
 * Thrown when every RPC endpoint failed to answer (timeouts, HTTP errors,
 * JSON-RPC error payloads) — as opposed to an RPC answering 0x, which means
 * the address genuinely has no code. Callers must NOT treat this as an EOA:
 * the item has to be retried later, not marked failed. A multi-day run
 * that marks RPC-outage items failed would burn the whole queue.
 */
export class RpcUnavailableError extends Error {
  constructor() {
    super("RPC_UNAVAILABLE: all RPC endpoints failed to answer (provider outage, not an EOA)");
    this.name = "RpcUnavailableError";
  }
}

/**
 * Fetch deployed runtime bytecode via eth_getCode over public EVM JSON-RPC
 */
async function fetchBytecodeRpc(address: string, rpcUrls: string[]): Promise<string | null> {
  // sawResult = at least one RPC answered with a usable result (even 0x).
  // Only then does "no bytecode" mean the address genuinely has no code.
  // If every RPC errored, the outage must surface as RpcUnavailableError.
  let sawResult = false;
  for (const rpcUrl of rpcUrls) {
    try {
      const res = await withRetry(async () => {
        await rpcLimiter.acquire();
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        try {
          return await fetch(rpcUrl, {
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
        } finally {
          clearTimeout(timer);
        }
      }, { retries: 1, baseDelayMs: 1500 });

      if (!res.ok) continue;
      const json = (await res.json()) as { result?: string; error?: unknown };
      const code = json.result;

      if (typeof code === "string") sawResult = true;
      if (code && typeof code === "string" && code !== "0x" && code.length > 4) {
        return code;
      }
    } catch {
      // try next RPC
    }
  }

  if (!sawResult) throw new RpcUnavailableError();
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
  customLabel?: string,
  opts?: {
    fourbyte?: FourbyteLookup;
    deployedName?: string | null;
    etherscanKey?: string;
    /**
     * ResNet1D runner, injected per environment (the worker passes the
     * Node runner from image-ml/resnet-node.server.ts; browser audit
     * flows pass image-ml/run-resnet-browser.ts). When supplied, EVERY
     * address entry — verified-source and bytecode-only alike — gets a
     * screening pass over its runtime bytecode before the report is
     * returned, and the report's riskScore includes the bounded ML
     * term. When omitted (e.g. a caller with no model available), the
     * audit is exactly the pre-ResNet one. Always fail-soft.
     */
    resnetRunner?: ResnetRunner;
  },
): Promise<{ report: Report; rawBody: string; inputKind: "source" | "bytecode" }> {
  if (!isValidEvmAddress(address)) {
    throw new Error(`Invalid EVM address format: ${address}`);
  }

  const chain = SUPPORTED_CHAINS.find((c) => c.id === chainId) ?? SUPPORTED_CHAINS[0]!;

  // Value at analysis time, attached to the inventory so it persists with the
  // record, renders in the UI, and drives the pre-run skip. Best-effort: a
  // provider outage leaves it unset (NOT zero) and is noted, never fatal.
  const attachValueAndAbi = async (r: Report): Promise<void> => {
    try {
      const value = await fetchAddressValue(address, chain.chainId, { rpcUrls: chain.rpcUrls });
      r.inventory.balanceWei = value.nativeWei;
      r.inventory.balanceSymbol = value.symbol;
      r.inventory.valueUsd = value.totalUsd;
      r.inventory.value = value;
      if (!value.complete) {
        r.inventory.notes = [...r.inventory.notes, `Value incomplete: ${value.notes.join("; ")}`];
      }
    } catch {
      // leave unset
    }
    // Gather the target ABI once and persist it with the record, so a later PoC
    // run in any context can tailor its template without re-fetching.
    try {
      const gathered = await gatherAbi(address, chain.chainId, {
        inventory: r.inventory,
        // Supplied by the server/worker caller; the browser has no key and
        // falls back to Sourcify, then to the heuristic ABI.
        etherscanKey: opts?.etherscanKey,
      });
      if (gathered) {
        r.inventory.abi = gathered.abi;
        r.inventory.abiSource = gathered.source;
      }
    } catch {
      // leave unset
    }
  };

  // 1. Try verified source: Sourcify first, then Blockscout (C1). A single
  //    registry is not a verdict on an address — the engagement's 19-of-21
  //    "unverified" contracts were all verified on the second one.
  const sourcifyMatch =
    (await fetchSourcifySource(address, chain.chainId)) ??
    (await fetchBlockscoutSource(address, chain.chainId));
  if (sourcifyMatch) {
    const label = customLabel || sourcifyMatch.name || `Verified (${address.slice(0, 6)}...)`;
    // Address audit: scope detection to the deployed contract (Item 2).
    // Sourcify single-file matches already pass the contract name;
    // multi-file matches rely on the deployed-name / most-derived
    // fallback inside analyzeInput. Callers that already probed name()
    // may pass opts.deployedName; the worker/workbench probe in parallel
    // with analysis, so they do not pass it today.
    const report = analyzeInput(sourcifyMatch.source, label, sourcifyMatch.contractName, {
      selectMainContract: true,
      deployedName: opts?.deployedName ?? null,
    });
    // Also fetch the runtime bytecode so the Bytecode & CFG tab works for
    // verified contracts. Before this, a Sourcify hit returned a source-only
    // report and the tab showed 0 opcodes / N/A size. Bytecode FINDINGS are
    // deliberately NOT merged (source findings already cover the logic) —
    // only the inventory fields the tab renders. If the bytecode fetch
    // fails (RPC outage), the source audit still stands — but the failure
    // is noted, so the tab's empty state is explained instead of silent.
    let bytecodeNote: string | null = null;
    try {
      const bytecode = await fetchBytecodeRpc(address, chain.rpcUrls);
      if (bytecode) {
        report.runtimeBytecode = { code: bytecode, sourceHash: sha3_256(sourcifyMatch.source) };
        const byte = analyzeBytecode(bytecode);
        const inv = report.inventory;
        inv.disassembly = byte.inventory.disassembly;
        inv.opcodes = byte.inventory.opcodes;
        if (inv.signals.length === 0) inv.signals = byte.inventory.signals;
        inv.bytecodeBytes = byte.inventory.bytecodeBytes;
        inv.basicBlocks = byte.inventory.basicBlocks;
        inv.proxy = inv.proxy ?? byte.inventory.proxy;
        // Source analysis has no selectors/topics (engine sets []), so
        // the bytecode's are ground truth — without this, verified
        // contracts get no fourbyte enrichment at all.
        if (inv.selectors.length === 0) inv.selectors = byte.inventory.selectors;
        if (!inv.topics || inv.topics.length === 0) inv.topics = byte.inventory.topics;
        inv.notes = [
          ...inv.notes,
          `Runtime bytecode also fetched (${byte.inventory.bytecodeBytes} bytes) — Bytecode & CFG tab reflects on-chain code.`,
        ];
      } else {
        bytecodeNote = "Runtime bytecode fetch returned no code — Bytecode & CFG tab unavailable for this audit.";
      }
    } catch {
      // Bytecode unavailable — source audit still stands.
      bytecodeNote = "Runtime bytecode fetch failed (RPC) — Bytecode & CFG tab unavailable for this audit.";
    }
    // Provenance of the source itself (C1) and of the label (C3): the
    // record states which registry answered and whether the display name
    // the caller supplied disagrees with the verified one. A dashboard
    // name is inferred, never fact — 9 of the engagement's 32 labels were
    // wrong, so both are reported instead of the inferred one silently
    // winning.
    report.inventory.verifiedName = sourcifyMatch.contractName ?? sourcifyMatch.name;
    report.inventory.labelCheck = customLabel && customLabel !== report.inventory.verifiedName
      ? `label_mismatch: display label "${customLabel}" differs from the verified name "${report.inventory.verifiedName}"`
      : "label_ok";
    report.inventory.notes = [
      ...report.inventory.notes,
      sourcifyMatch.registry === "blockscout"
        ? "Source came from Blockscout — Sourcify had no match for this address (second-registry fallback)."
        : "Source came from Sourcify (verified match).",
    ];
    if (bytecodeNote) report.inventory.notes = [...report.inventory.notes, bytecodeNote];
    // Resolve unknown selectors + event topics against the 4byte tables
    // (worker / server callers pass a DB lookup; the browser workbench
    // enriches via the resolveFourbyte server fn instead).
    if (opts?.fourbyte) await enrichReportFourbyte(report, opts.fourbyte);
    await attachValueAndAbi(report);
    // Initializer live-state gate (Fix 37): unprotected-initializer
    // findings arrive capped at high from the detector; with the ABI
    // now gathered, this probe is the only route back to critical —
    // a candidate missing from the deployed ABI is dropped (it
    // belongs to another contract in the compilation), and positive
    // live evidence (an uninitialized state read, or a simulated call
    // from a fresh address that succeeds and moves privileged state)
    // restores critical + corroborated. Everything else keeps the
    // cap. Fail-soft and fail-closed: a probe failure changes nothing.
    try {
      await applyInitializerGate(report, {
        address,
        chainId: chain.id,
        source: sourcifyMatch.source,
      });
    } catch {
      // the gate never throws by construction; belt-and-braces
    }
    // Live-state evidence (2026-10-22): for verified-source audits with
    // at least one high/critical finding, probe the contract's decisive
    // getters (paused / owner / trading flags / fees / limits) over RPC
    // and attach the LIVE values to the inventory — the adjudication
    // counterpart to source-argued closures (constructor defaults and
    // initial values can differ from live mutable state). Evidence
    // only: findings are NOT re-scored. Never throws; skipped silently
    // when the contract exposes no decisive getters.
    if (report.findings.some((f) => f.severity === "critical" || f.severity === "high")) {
      try {
        const liveState = await gatherLiveState(address, chain.id, {
          source: sourcifyMatch.source,
          abi: report.inventory.abi,
        });
        if (liveState) report.inventory.liveState = liveState;
      } catch {
        // evidence is best-effort — the audit stands without it
      }
    }
    // ResNet1D screening over the runtime bytecode fetched above — the
    // same code the Bytecode & CFG tab renders. Without the runtime
    // fetch this path would have nothing to classify: the screening
    // consumes report.runtimeBytecode, never the source text. Skipped
    // silently when the bytecode fetch failed (already noted above).
    if (opts?.resnetRunner) {
      await attachResnetToReport(report, runtimeCodeForReport(report), opts.resnetRunner);
    }
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

  // 2b. Identity for an address no registry verified (C2/C3). Blockscout
  //     answers for unverified contracts too, so the audit gets a real
  //     name, a proxy shape and a creation-bytecode route instead of the
  //     old "unreadable" label. Best-effort: a failure changes nothing.
  const identity = await fetchBlockscoutIdentity(address, chain.chainId).catch(() => null);

  const label = customLabel || bytecodeAnalysedLabel(address, identity);
  const report = analyzeInput(bytecode, label);
  report.inventory.notes = [...report.inventory.notes, bytecodeAnalysedNote(identity)];
  report.inventory.verifiedName = null;
  report.inventory.labelCheck = customLabel && identity?.name && customLabel !== identity.name
    ? `label_mismatch: display label "${customLabel}" differs from the registry name "${identity.name}" (unverified contract)`
    : "label_unverified";

  if (opts?.fourbyte) await enrichReportFourbyte(report, opts.fourbyte);
  await attachValueAndAbi(report);

  // ResNet1D screening: this path's whole input IS the runtime code.
  if (opts?.resnetRunner) {
    await attachResnetToReport(report, runtimeCodeForReport(report, bytecode), opts.resnetRunner);
  }

  return {
    report,
    rawBody: bytecode,
    inputKind: "bytecode",
  };
}
