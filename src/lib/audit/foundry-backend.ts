import type { PocResult } from "./types";

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
export async function runPocOnBackend(
  url: string,
  input: {
    address: string;
    testCode: string;
    rpcUrl?: string;
    rpcUrls?: string[];
    blockNumber?: number;
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
export async function runPocWithRpcRetries(
  backendUrl: string,
  input: {
    address: string;
    testCode: string;
    preferredRpc?: string;
    rpcList?: string[];
    blockNumber?: number;
    onProgress?: (progress: RpcRetryProgress) => void;
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
  for (const f of FALLBACK_RPC_LIST) {
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

    const res = await runPocOnBackend(backendUrl, {
      address: input.address,
      testCode: input.testCode,
      rpcUrl: rpc,
      rpcUrls: candidates,
      blockNumber: input.blockNumber,
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
