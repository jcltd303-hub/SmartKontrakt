import { useEffect, useState } from "react";
import { Play, Loader2, CheckCircle2, XCircle, Server, AlertTriangle } from "lucide-react";

/**
 * FoundryLocalRun — run the AI-generated Foundry exploit test against a
 * live-net fork via the Termux local backend (http://127.0.0.1:8787).
 *
 * The Vercel app can never shell out to forge (serverless). The backend runs
 * on Jer's own phone under Termux and shells out to HIS forge binary. The
 * browser (HTTPS app) fetches the loopback backend (http://localhost) — 
 * browsers exempt loopback from mixed-content blocking, so this works.
 *
 * Wiring (see wiring note at the bottom): render inside the workbench AI
 * tab, next to the generated Foundry test / FoundryExport.
 */
interface FoundryLocalRunProps {
  /** Generated Foundry test code (aiReview.foundryTestCode). Must declare `contract PoC`. */
  testCode: string;
  /** Address of the audited contract, if the workbench fetched one. */
  address: string;
  /** Upstream RPC the backend forks from. Defaults to the backend's ETH_RPC_URL / public endpoint. */
  rpcUrl?: string;
}

type Health = { ok: boolean; forge: boolean; anvil: boolean } | null;
type RunResult = {
  ok: boolean;
  passed: boolean;
  logs: string;
  durationMs: number;
  error?: string;
} | null;

const BACKEND_KEY = "sk-foundry-backend-url";
const DEFAULT_BACKEND = "http://127.0.0.1:8787";
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

async function fetchWithTimeout(url: string, init: RequestInit, ms: number) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

export function FoundryLocalRun({ testCode, address, rpcUrl }: FoundryLocalRunProps) {
  const [backendUrl, setBackendUrl] = useState(DEFAULT_BACKEND);
  const [health, setHealth] = useState<Health>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<RunResult>(null);
  const [runError, setRunError] = useState<string | null>(null);

  useEffect(() => {
    try {
      const saved = localStorage.getItem(BACKEND_KEY);
      if (saved) setBackendUrl(saved);
    } catch {
      // localStorage unavailable — default stands.
    }
  }, []);

  const saveBackendUrl = (v: string) => {
    setBackendUrl(v);
    try {
      localStorage.setItem(BACKEND_KEY, v);
    } catch {
      // ignore — persistence is a nicety
    }
  };

  const addressValid = ADDRESS_RE.test(address.trim());

  const checkBackend = async () => {
    setChecking(true);
    setHealthError(null);
    try {
      const res = await fetchWithTimeout(`${backendUrl.replace(/\/$/, "")}/health`, {}, 10_000);
      if (!res.ok) throw new Error(`backend answered ${res.status}`);
      setHealth((await res.json()) as Health);
    } catch {
      setHealth(null);
      setHealthError("Backend not reachable");
    } finally {
      setChecking(false);
    }
  };

  const runPoc = async () => {
    setRunning(true);
    setRunError(null);
    setResult(null);
    try {
      const res = await fetchWithTimeout(
        `${backendUrl.replace(/\/$/, "")}/run-poc`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            address: address.trim(),
            testCode,
            ...(rpcUrl ? { rpcUrl } : {}),
          }),
        },
        180_000, // covers the backend's 120s forge timeout + overhead
      );
      const data = (await res.json()) as RunResult & { error?: string };
      if (!res.ok && res.status !== 500) {
        throw new Error((data as { error?: string })?.error ?? `backend answered ${res.status}`);
      }
      setResult(data);
    } catch (err) {
      setRunError(
        err instanceof Error && err.name === "AbortError"
          ? "Timed out waiting for the backend (forge runs cap at 120s — check Termux)"
          : "Backend not reachable — start it in Termux (see below), then retry.",
      );
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="mt-2 p-3 bg-[#12110e] rounded-lg border border-[#3a3428] flex flex-col gap-2">
      <div className="flex items-center gap-1.5 text-xs font-mono font-bold text-[#e8a54b]">
        <Server className="w-3.5 h-3.5" />
        <span>Run this PoC on your local backend (Termux + Foundry, fork-only)</span>
      </div>
      <p className="text-[11px] font-mono text-[#a39886] leading-relaxed">
        Executes the test against a fork of live chain state on your phone. Nothing is broadcast,
        nothing is spent, no private key is involved. The backend runs one PoC at a time.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <label className="text-[11px] font-mono text-[#a39886]">Backend</label>
        <input
          type="text"
          value={backendUrl}
          onChange={(e) => saveBackendUrl(e.target.value)}
          className="flex-1 min-w-44 bg-[#12110e] border border-[#3a3428] rounded px-2 py-1 text-xs text-[#f4efe6] font-mono focus:outline-none focus:border-[#e8a54b]"
        />
        <button
          onClick={checkBackend}
          disabled={checking}
          className="text-xs font-mono px-2.5 py-1.5 rounded border border-[#3a3428] text-[#f4efe6] flex items-center gap-1.5 hover:border-[#e8a54b] disabled:opacity-50"
        >
          {checking ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Server className="w-3.5 h-3.5" />}
          {checking ? "Checking…" : "Check backend"}
        </button>
      </div>

      {health && (
        <p className="text-[11px] font-mono text-[#a39886]">
          Backend up — forge:{" "}
          <span className={health.forge ? "text-emerald-400 font-bold" : "text-red-400 font-bold"}>
            {health.forge ? "yes" : "MISSING"}
          </span>
          {", anvil: "}
          <span className={health.anvil ? "text-emerald-400 font-bold" : "text-[#a39886]"}>
            {health.anvil ? "yes" : "not installed (optional — forge forks directly)"}
          </span>
        </p>
      )}
      {healthError && (
        <div className="text-[11px] font-mono text-amber-300 bg-amber-950/30 border border-amber-900/50 rounded p-2 leading-relaxed">
          <span className="font-bold">Backend not reachable.</span> Start it in Termux:
          <pre className="mt-1 text-[#f4efe6] whitespace-pre-wrap">cd ~/SmartKontrakt && node termux-backend/server.mjs</pre>
        </div>
      )}

      {!addressValid && (
        <p className="text-[11px] font-mono text-amber-300 flex items-center gap-1">
          <AlertTriangle className="w-3.5 h-3.5" /> No valid 0x target address — fetch an on-chain address first.
        </p>
      )}

      <button
        onClick={runPoc}
        disabled={running || !addressValid || !testCode.trim()}
        className="w-fit text-xs font-mono px-3 py-1.5 rounded bg-[#e8a54b] text-[#12110e] font-bold flex items-center gap-1.5 hover:bg-[#f0b25e] disabled:opacity-50"
      >
        {running ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
        {running ? "Running PoC on local backend…" : "Run PoC on local backend"}
      </button>

      {runError && (
        <div className="text-[11px] font-mono text-amber-300 bg-amber-950/30 border border-amber-900/50 rounded p-2 leading-relaxed">
          <span className="font-bold">{runError}</span>
          <pre className="mt-1 text-[#f4efe6] whitespace-pre-wrap">cd ~/SmartKontrakt && node termux-backend/server.mjs</pre>
        </div>
      )}

      {result && (
        <div className="flex flex-col gap-2">
          <div
            className={`flex items-center gap-1.5 text-xs font-mono font-bold ${
              result.passed ? "text-emerald-400" : "text-red-400"
            }`}
          >
            {result.passed ? (
              <CheckCircle2 className="w-4 h-4" />
            ) : (
              <XCircle className="w-4 h-4" />
            )}
            {result.passed
              ? `PoC PASSED — exploit reproduced on fork (${result.durationMs}ms)`
              : result.error
                ? `Backend error: ${result.error}`
                : `PoC FAILED — exploit did not reproduce on fork (${result.durationMs}ms)`}
          </div>
          {!result.passed && !result.error && (
            <p className="text-[11px] font-mono text-[#a39886]">
              Failure is the signal, not a bug: guarded target, wrong interface, or fork state moved.
            </p>
          )}
          <pre className="max-h-96 overflow-y-auto bg-[#0a0908] border border-[#3a3428] rounded p-2 text-[11px] font-mono text-[#f4efe6] whitespace-pre-wrap">
            {result.logs || "(no output)"}
          </pre>
        </div>
      )}
    </div>
  );
}

/*
WIRING (in src/components/workbench.tsx — do NOT edit that file here):

1. Import (top of file, next to the other component imports):
     import { FoundryLocalRun } from "./foundry-local-run";

2. In the AI tab, inside the "Foundry Exploit Verification Test" block,
   right after <FoundryExport ... />, add:
     <FoundryLocalRun
       testCode={aiReview.foundryTestCode}
       address={singleAddress}
     />

3. Done — no props drilling, no server changes, no new deps (lucide-react
   is already used by the workbench).
*/
