import type { PocResult } from "./types";
import { sha3_256 } from "js-sha3";
import { wrapPocSnippet } from "./poc-wrap.ts";
import { nativeSymbol } from "./balance.ts";
import { fetchAddressValue, isZeroValue } from "./value.ts";

/**
 * Forge compile-error detector for PoC logs. Compile failures are the
 * repairable kind — the model can fix a syntax/interface error from the
 * compiler output. Infra failures (RPC down, timeout, backend busy) are
 * NOT repairable by editing the PoC, so they must not trigger a repair
 * LLM call. Used by the workbench loop and the worker Deep Agent loop.
 */
export function isPocCompileError(logs: string): boolean {
  if (!logs) return false;
  return /(compiler run failed|compilation failed|failed to compile|error\[\d+\]|error\s*\(\d+\)|parsererror|declarationerror|typeerror)/i.test(logs);
}

/**
 * Client for the Termux Foundry local backend (http://127.0.0.1:8787).
 *
 * Shared by the manual "Run PoC" component and the auto-run that fires when
 * a PoC is generated, so both paths map backend responses to PocResult the
 * same way. Browser-side only — never imported by server code.
 */

export const BACKEND_KEY = "sk-foundry-backend-url";
export const DEFAULT_BACKEND = "http://127.0.0.1:8787";
export const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

export function getBackendUrl(): string {
  try {
    return localStorage.getItem(BACKEND_KEY) ?? DEFAULT_BACKEND;
  } catch {
    return DEFAULT_BACKEND;
  }
}

async function fetchWithTimeout(url: string, init: RequestInit, ms: number) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

export type BackendHealth = { ok: boolean; forge: boolean; anvil: boolean } | null;

export async function checkFoundryBackend(url = getBackendUrl()): Promise<BackendHealth> {
  try {
    const res = await fetchWithTimeout(`${url.replace(/\/$/, "")}/health`, {}, 10_000);
    if (!res.ok) return null;
    return (await res.json()) as BackendHealth;
  } catch {
    return null;
  }
}

/**
 * Detects whether logs or error message indicate an RPC, transport, fork setup, or rate-limit failure.
 * When true, running the test with another RPC provider is necessary and viable.
 */
export function isRpcOrForkFailure(logs: string, error?: string): boolean {
  const text = `${logs ?? ""} ${error ?? ""}`;
  if (!text.trim()) return false;
  // Compile errors are syntax/Solidity issues, NOT RPC issues
  if (isPocCompileError(text)) return false;
  return /invalid rpc url|vm\.createSelectFork|vm\.createFork|createSelectFork|createFork|HTTP error|failed to (fetch|get).*chain|failed to fetch|error sending request|connection (refused|reset|aborted|timed? ?out)|connect timed? ?out|request timed? ?out|operation timed? ?out|rate ?limit|too many requests|\b429\b|\b502\b|\b503\b|\b504\b|\b525\b|failed to (instantiate|create|setup).*fork|fork.*(instantiation|creation) failed|Failed to get (chain|block)|eth_chainId|JSON-RPC.*error|could not resolve host|DNS.*lookup failed|transport error|block.*not found|out of range/i.test(
    text,
  );
}

export const FALLBACK_RPC_LIST: string[] = [
  "https://ethereum.publicnode.com",
  "https://eth.drpc.org",
  "https://1rpc.io/eth",
  "https://cloudflare-eth.com",
  "https://eth.llamarpc.com",
  "https://arb1.arbitrum.io/rpc",
  "https://arbitrum.llamarpc.com",
  "https://arbitrum-one.publicnode.com",
  "https://1rpc.io/arb",
  "https://mainnet.base.org",
  "https://base.llamarpc.com",
  "https://base.publicnode.com",
  "https://mainnet.optimism.io",
  "https://polygon-rpc.com",
  "https://bsc-dataseed.binance.org",
];

/**
 * Run a generated PoC test against the local backend's live-net fork.
 * Never rejects for backend-level failures — they map to PocResult statuses
 * ("error", "backend_unreachable", "skipped") so callers can persist them.
 */
async function requestPocOnBackend(
  url: string,
  input: {
    address: string;
    testCode: string;
    rpcUrl?: string;
    rpcUrls?: string[];
    blockNumber?: number;
    /** Optional ERC-20 the harness should judge (template 46's
     *  POC_TOKEN). Forwarded only when it is a valid address; absent =
     *  the backend leaves POC_TOKEN unset and the template defaults to
     *  the target-as-its-own-token. */
    tokenAddress?: string;
  },
): Promise<PocResult> {
  const started = Date.now();
  const runAt = () => new Date().toISOString();
  const address = input.address.trim();
  if (!ADDRESS_RE.test(address)) {
    return { status: "skipped", logs: "No valid 0x target address — fetch an on-chain address first.", durationMs: 0, runAt: runAt() };
  }
  if (!input.testCode.trim()) {
    return { status: "skipped", logs: "No Foundry test code to run.", durationMs: 0, runAt: runAt() };
  }
  try {
    const res = await fetchWithTimeout(
      `${url.replace(/\/$/, "")}/run-poc`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          address,
          testCode: input.testCode,
          ...(input.rpcUrl ? { rpcUrl: input.rpcUrl } : {}),
          ...(input.rpcUrls && input.rpcUrls.length > 0 ? { rpcUrls: input.rpcUrls } : {}),
          ...(input.blockNumber !== undefined ? { blockNumber: input.blockNumber } : {}),
          ...(input.tokenAddress && ADDRESS_RE.test(input.tokenAddress)
            ? { tokenAddress: input.tokenAddress }
            : {}),
        }),
      },
      180_000, // covers the backend's 120s forge timeout + overhead
    );
    const data = (await res.json()) as {
      ok: boolean;
      passed: boolean;
      logs: string;
      durationMs: number;
      error?: string;
    };
    if (!res.ok && res.status !== 500) {
      return {
        status: "error",
        logs: data?.error ?? `Backend answered ${res.status}`,
        durationMs: Date.now() - started,
        runAt: runAt(),
        error: data?.error ?? `Backend answered ${res.status}`,
      };
    }
    if (!data.ok) {
      return {
        status: "error",
        logs: data.logs || data.error || "Backend failed to run forge.",
        durationMs: data.durationMs ?? Date.now() - started,
        runAt: runAt(),
        error: data.error,
      };
    }
    return {
      status: data.passed ? "passed" : "failed",
      logs: data.logs || "(no output)",
      durationMs: data.durationMs ?? Date.now() - started,
      runAt: runAt(),
    };
  } catch (err) {
    const timedOut = err instanceof Error && err.name === "AbortError";
    return {
      status: "backend_unreachable",
      logs: timedOut
        ? "Timed out waiting for the backend (forge runs cap at 120s — check Termux)."
        : "Backend not reachable — start it in Termux (cd ~/SmartKontrakt && node termux-backend/server.mjs), then retry.",
      durationMs: Date.now() - started,
      runAt: runAt(),
    };
  }
}

export type RpcRetryProgress = {
  attempt: number;
  total: number;
  rpcUrl: string;
  status: "trying" | "passed" | "failed" | "error";
  error?: string;
};

/**
 * Execute a PoC with automatic retry across candidate RPC providers.
 * If an RPC provider fails with transport/fork/invalid rpc url errors,
 * the run automatically falls back to the next RPC in the list.
 */
async function executeWithRpcRetries(
  backendUrl: string,
  input: {
    address: string;
    testCode: string;
    preferredRpc?: string;
    rpcList?: string[];
    blockNumber?: number;
    chainId?: number | string;
    retry?: boolean;
    repair?: (source: string, logs: string) => Promise<string>;
    onProgress?: (progress: RpcRetryProgress) => void;
    /** Optional ERC-20 for the harness to judge (template 46's
     *  POC_TOKEN) — forwarded to the backend on every attempt. */
    tokenAddress?: string;
    /**
     * Pre-run guard (default on): value the target (native + ERC-20s, in USD) and
     * skip the run when the total is a CONFIRMED zero — nothing at stake. An
     * incomplete valuation never skips. Set false to force the run.
     */
    skipZeroValue?: boolean;
  },
): Promise<PocResult & { triedRpcs: string[]; finalRpc?: string }> {
  const candidateSet = new Set<string>();
  if (input.preferredRpc && input.preferredRpc.trim()) {
    candidateSet.add(input.preferredRpc.trim());
  }
  if (input.rpcList && input.rpcList.length > 0) {
    for (const r of input.rpcList) {
      if (r && r.trim()) candidateSet.add(r.trim());
    }
  }
  for (const f of (input.retry === false ? [] : rpcCandidates(input.chainId))) {
    candidateSet.add(f);
  }
  const candidates = Array.from(candidateSet);
  const triedRpcs: string[] = [];

  let lastResult: PocResult = {
    status: "skipped",
    logs: "No RPC candidates to run.",
    durationMs: 0,
    runAt: new Date().toISOString(),
  };

  for (let i = 0; i < candidates.length; i++) {
    const rpc = candidates[i];
    triedRpcs.push(rpc);
    input.onProgress?.({
      attempt: i + 1,
      total: candidates.length,
      rpcUrl: rpc,
      status: "trying",
    });

    const res = await requestPocOnBackend(backendUrl, {
      address: input.address,
      testCode: input.testCode,
      rpcUrl: rpc,
      rpcUrls: [rpc],
      blockNumber: input.blockNumber,
      tokenAddress: input.tokenAddress,
    });
    lastResult = res;

    // PoC succeeded on fork!
    if (res.status === "passed") {
      input.onProgress?.({
        attempt: i + 1,
        total: candidates.length,
        rpcUrl: rpc,
        status: "passed",
      });
      return { ...res, triedRpcs, finalRpc: rpc };
    }

    // Backend itself is not reachable — no point cycling RPCs if the local server is down
    if (res.status === "backend_unreachable") {
      input.onProgress?.({
        attempt: i + 1,
        total: candidates.length,
        rpcUrl: rpc,
        status: "error",
        error: "Backend unreachable",
      });
      return { ...res, triedRpcs, finalRpc: rpc };
    }

    // Solc compile error — Solidity code issue, not an RPC issue
    if (isPocCompileError(res.logs ?? "")) {
      input.onProgress?.({
        attempt: i + 1,
        total: candidates.length,
        rpcUrl: rpc,
        status: "error",
        error: "Solidity compilation error",
      });
      return { ...res, triedRpcs, finalRpc: rpc };
    }

    // Real test verdict (failed assertions on fork, not an RPC error)
    const isRpcFail = isRpcOrForkFailure(res.logs ?? "", res.error);
    if (!isRpcFail && !res.logs?.includes("invalid rpc url")) {
      input.onProgress?.({
        attempt: i + 1,
        total: candidates.length,
        rpcUrl: rpc,
        status: "failed",
      });
      return { ...res, triedRpcs, finalRpc: rpc };
    }

    // It was an RPC failure, log and try next candidate!
    input.onProgress?.({
      attempt: i + 1,
      total: candidates.length,
      rpcUrl: rpc,
      status: "error",
      error: `RPC ${rpc} failed (transport/fork error) — trying next provider in list`,
    });
  }

  return {
    ...lastResult,
    logs: `${lastResult.logs}\n\n[Kiln: All ${candidates.length} candidate RPCs in list were tried. Last attempted: ${triedRpcs[triedRpcs.length - 1]}]`,
    triedRpcs,
    finalRpc: triedRpcs[triedRpcs.length - 1],
  };
}



const CHAIN_RPCS: Record<number, string[]> = {
  1: FALLBACK_RPC_LIST.slice(0, 5),
  42161: FALLBACK_RPC_LIST.slice(5, 9),
  8453: [...FALLBACK_RPC_LIST.slice(9, 12), "https://1rpc.io/base"],
  10: ["https://mainnet.optimism.io", "https://optimism.publicnode.com", "https://1rpc.io/op"],
  137: ["https://polygon-rpc.com", "https://polygon-bor-rpc.publicnode.com", "https://1rpc.io/matic"],
  56: ["https://bsc-dataseed.binance.org", "https://bsc.publicnode.com", "https://1rpc.io/bnb"],
};
function rpcCandidates(chain?: number | string): string[] {
  const names: Record<string, number> = { ethereum: 1, arbitrum: 42161, base: 8453, optimism: 10, polygon: 137, bsc: 56 };
  const id = names[String(chain)] ?? Number(chain ?? 1);
  return CHAIN_RPCS[id] ?? [];
}

export function needsSmartPoc(finding: {
  exploitSolidity?: string; pocCode?: string | null; pocStatus?: string | null; pocRunAt?: string | null; pocOutput?: string | null;
}): boolean {
  return Boolean(finding.exploitSolidity?.trim()) && !(
    ["passed", "failed"].includes(finding.pocStatus ?? "") && finding.pocRunAt &&
    finding.pocOutput?.includes("[SmartPoC | Foundry]") && /tests=[1-9]\d*/.test(finding.pocOutput) &&
    (finding.pocOutput.includes(`Finding input SHA3-256: ${pocInputDigest(finding.exploitSolidity ?? "")}`) || finding.pocCode === finding.exploitSolidity || finding.pocCode === wrapPocSnippet(finding.exploitSolidity ?? "")?.testFile)
  );
}

/** Shared execution entry point for UI and workers. Evidence describes actual
 * Foundry responses; infrastructure failures and zero tests are never verdicts. */
export async function runSmartPoc(
  backendUrl: string,
  input: Parameters<typeof executeWithRpcRetries>[1],
): Promise<Awaited<ReturnType<typeof executeWithRpcRetries>>> {
  const startedAt = new Date().toISOString();

  // Quick pre-run value check: value the target (native + ERC-20s, USD) at the
  // latest block and skip when there is nothing at stake. Only a CONFIRMED zero
  // skips — an incomplete valuation (provider down, chain we cannot read) runs.
  // See skipZeroValue to force a run.
  if (input.skipZeroValue !== false) {
    const rpcs = input.rpcList && input.rpcList.length ? input.rpcList : rpcCandidates(input.chainId);
    const value = await fetchAddressValue(input.address, input.chainId, { rpcUrls: rpcs }).catch(() => null);
    if (isZeroValue(value) && value) {
      return {
        status: "skipped",
        logs: `[SmartPoC] Skipped — target ${input.address} holds no value (0 ${nativeSymbol(input.chainId)}, no priced token holdings) at the latest block, so there is nothing at stake to exploit. Pass skipZeroValue: false to run anyway.`,
        durationMs: 0,
        runAt: new Date().toISOString(),
        executedSource: input.testCode,
        triedRpcs: [],
        valueUsd: value.totalUsd,
      };
    }
  }

  const bytes = new TextEncoder().encode(input.testCode);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const sourceHash = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
  const result = await executeWithRpcRetries(backendUrl, input);
  if (result.status === "failed" && isPocCompileError(result.logs)) result.status = "error";
  if (result.status === "error" && isPocCompileError(result.logs) && input.repair) {
    try {
      const fixedCode = await input.repair(input.testCode, result.logs);
      const repaired = await runSmartPoc(backendUrl, { ...input, testCode: fixedCode, repair: undefined });
      repaired.logs = `[SmartPoC] One compile repair attempted.\n${repaired.logs}`;
      return repaired;
    } catch (repairError) { result.logs += `\nSmartPoC repair failed: ${String(repairError)}`; }
  }
  result.executedSource = input.testCode;
  const summary = result.logs.match(/(\d+) passed;\s*(\d+) failed/i);
  const testCount = summary ? Number(summary[1]) + Number(summary[2]) : (result.logs.match(/\[(?:PASS|FAIL[^\]]*)\]/g) ?? []).length;
  if (["passed", "failed"].includes(result.status) && testCount === 0) {
    // Zero executed tests is its own outcome kind, NOT an error: the
    // harness ran (or matched nothing) but no test function executed,
    // so there is no verdict and nothing "failed". It persists as
    // poc_status 'no_tests' (see poc-outcome.ts) instead of polluting
    // the error bucket.
    result.status = "no_tests";
    result.error = "No executed Foundry tests were evidenced in the backend output.";
  }
  result.evidence = { engine: "foundry", startedAt, finishedAt: result.runAt,
    target: input.address, chainId: String(input.chainId ?? 1), sourceHash,
    backendUrl, rpcUrls: result.triedRpcs, testCount };
  result.logs = `[SmartPoC | Foundry] target=${input.address} chain=${input.chainId ?? 1} tests=${testCount}\nSHA-256: ${sourceHash}\nExecuted source SHA3-256: ${sha3_256(input.testCode)}\nStarted: ${startedAt}\nFinished: ${result.runAt}\nRPC attempts: ${result.triedRpcs.join(", ")}\n${result.logs}${result.error ? "\n" + result.error : ""}`;
  return result;
}

// Compatibility name: every existing retry caller now uses SmartPoC evidence.
export const runPocWithRpcRetries = runSmartPoc;

export async function runPocOnBackend(url: string, input: Parameters<typeof requestPocOnBackend>[1] & { chainId?: string | number; repair?: (source: string, logs: string) => Promise<string> }): Promise<PocResult> {
  return runSmartPoc(url, { ...input, preferredRpc: input.rpcUrl ?? rpcCandidates(input.chainId)[0], rpcList: input.rpcUrls, retry: false });
}

export async function runMissingSmartPocs<T extends { severity: string; exploitSolidity?: string; pocCode?: string | null; pocStatus?: string | null; pocRunAt?: string | null }>(
  findings: T[], execute: (finding: T) => Promise<{ status: string } | undefined>,
  cancelled: () => boolean = () => false,
): Promise<void> {
  for (const finding of findings) {
    if (cancelled()) break;
    if (!["critical", "high"].includes(finding.severity) || !needsSmartPoc(finding)) continue;
    const result = await execute(finding);
    if (result?.status === "backend_unreachable") break;
  }
}

export const pocInputDigest = (source: string): string => sha3_256(source);
