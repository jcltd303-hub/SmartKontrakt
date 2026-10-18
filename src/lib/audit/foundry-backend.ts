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
 * Run a generated PoC test against the local backend's live-net fork.
 * Never rejects for backend-level failures — they map to PocResult statuses
 * ("error", "backend_unreachable", "skipped") so callers can persist them.
 */
export async function runPocOnBackend(
  url: string,
  input: { address: string; testCode: string; rpcUrl?: string },
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
