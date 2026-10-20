import { PocEvidenceBadge } from "@/components/poc-evidence-badge";
import { classifyPocEvidence } from "@/lib/audit/poc-evidence";
import type { PocOrigin } from "@/lib/audit/poc-evidence";
import { requestPocRepair } from "@/lib/audit/ai.functions";
import { useEffect, useState } from "react";
import { Play, Loader2, Server, AlertTriangle } from "lucide-react";
import {
  ADDRESS_RE,
  BACKEND_KEY,
  DEFAULT_BACKEND,
  checkFoundryBackend,
  runPocOnBackend,
  runPocWithRpcRetries,
  isRpcOrForkFailure,
  type BackendHealth,
  type RpcRetryProgress,
} from "@/lib/audit/foundry-backend";
import { saveSmartPocResult } from "@/lib/audit/smart-poc-save";
import { getStoredSupabaseConfig } from "@/lib/supabase";
import { SUPPORTED_CHAINS } from "@/lib/audit/address-fetcher";
import type { PocResult } from "@/lib/audit/types";
import { RotateCw } from "lucide-react";

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
  origin?: PocOrigin;
  /** Address of the audited contract, if the workbench fetched one. */
  address: string;
  /** Upstream RPC the backend forks from. Defaults to the backend's ETH_RPC_URL / public endpoint. */
  rpcUrl?: string;
  chainId?: string;
  contractName?: string;
  contractBody?: string;
}

type Health = BackendHealth;
type RunResult = (PocResult & { passed: boolean }) | null;

export function FoundryLocalRun({ testCode, origin = "generated", address, rpcUrl, chainId = "ethereum", contractName = "Contract", contractBody = "" }: FoundryLocalRunProps) {
  const [backendUrl, setBackendUrl] = useState(DEFAULT_BACKEND);
  const [health, setHealth] = useState<Health>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<RunResult>(null);
  const [saveNotice, setSaveNotice] = useState("");
  const [runError, setRunError] = useState<string | null>(null);
  const [retryAllRpcs, setRetryAllRpcs] = useState(true);
  const [retryProgress, setRetryProgress] = useState<RpcRetryProgress | null>(null);

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
      const health = await checkFoundryBackend(backendUrl);
      if (!health) throw new Error("unreachable");
      setHealth(health);
    } catch {
      setHealth(null);
      setHealthError("Backend not reachable");
    } finally {
      setChecking(false);
    }
  };

  const runPoc = async (forceRetryAll = false) => {
    setRunning(true);
    setSaveNotice("");
    let completed: PocResult | null = null;
    setRunError(null);
    setResult(null);
    setRetryProgress(null);

    const shouldRetry = forceRetryAll || retryAllRpcs;
    const repair = async (source: string, logs: string) => {
      const response = await requestPocRepair({ data: { contractName, originalCode: source, errorLogs: logs, body: contractBody } });
      return response.fixedCode;
    };

    if (shouldRetry) {
      const poc = await runPocWithRpcRetries(backendUrl, {
        address,
        chainId,
        testCode,
        preferredRpc: rpcUrl,
        repair,
        onProgress: (p) => setRetryProgress(p),
      });
      completed = poc;
      if (poc.status === "backend_unreachable") {
        setRunError(poc.logs);
      } else {
        setResult({ ...poc, passed: poc.status === "passed" });
      }
    } else {
      const poc = await runPocOnBackend(backendUrl, { address, testCode, chainId, repair, ...(rpcUrl ? { rpcUrl } : {}) });
      completed = poc;
      if (poc.status === "backend_unreachable") {
        setRunError(poc.logs);
      } else {
        setResult({ ...poc, passed: poc.status === "passed" });
      }
    }
    try {
      if (completed) setSaveNotice(await saveSmartPocResult(completed, completed.executedSource ?? testCode,
        SUPPORTED_CHAINS.find(c => c.id === chainId)?.chainId ?? Number(chainId), getStoredSupabaseConfig()));
    } catch (saveError) { setSaveNotice(`Save failed: ${String(saveError)}`); }
    setRunning(false);
  };

  return (
    <div className="mt-2 p-3 bg-[#12110e] rounded-lg border border-[#3a3428] flex flex-col gap-2">
      <div className="flex items-center gap-1.5 text-xs font-mono font-bold text-[#e8a54b]">
        <Server className="w-3.5 h-3.5" />
        <span>SmartPoC · Foundry fork execution</span>
      </div>
      {saveNotice && <p className="text-xs" role="status">Persistence: {saveNotice}</p>}
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

      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-1.5 text-[11px] font-mono text-[#a39886] cursor-pointer">
          <input
            type="checkbox"
            checked={retryAllRpcs}
            onChange={(e) => setRetryAllRpcs(e.target.checked)}
            className="rounded border-[#3a3428] text-[#e8a54b] focus:ring-0 bg-[#12110e]"
          />
          <span>Retry using all RPCs in list when necessary</span>
        </label>
        {result && !result.passed && isRpcOrForkFailure(result.logs ?? "", result.error) && (
          <button
            onClick={() => runPoc(true)}
            disabled={running}
            className="text-[11px] font-mono text-amber-400 hover:text-amber-300 flex items-center gap-1 disabled:opacity-50"
          >
            <RotateCw className="w-3 h-3" />
            <span>Retry All Candidate RPCs</span>
          </button>
        )}
      </div>

      {retryProgress && (
        <div className="text-[11px] font-mono text-blue-300 bg-blue-950/30 border border-blue-900/50 rounded p-1.5 flex items-center gap-1.5">
          <RotateCw className="w-3 h-3 animate-spin text-blue-400 shrink-0" />
          <span>
            [Attempt {retryProgress.attempt}/{retryProgress.total}] Testing with {retryProgress.rpcUrl}...
          </span>
        </div>
      )}

      <button
        onClick={() => runPoc(false)}
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
          <PocEvidenceBadge evidence={classifyPocEvidence({ code: testCode, origin, result, target: address, chainId })} />
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

