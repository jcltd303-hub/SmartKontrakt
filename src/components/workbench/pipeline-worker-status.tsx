import { useEffect, useState } from "react";
import { Play, Pause, Square, Loader2, Server, AlertTriangle } from "lucide-react";

/**
 * PipelineWorkerStatus — monitor + controls for the headless pipeline
 * worker (pipeline-worker/worker.ts) that runs on Jer's phone in Termux.
 *
 * The worker survives browser close; this panel polls its /status endpoint
 * (loopback, same pattern as FoundryLocalRun) and POSTs start/pause/resume/
 * stop. Client-side only — no server call, no keys.
 *
 * WIRING (in src/components/workbench/batch-pipeline.tsx — do NOT edit that
 * file here):
 *
 * 1. Import:  import { PipelineWorkerStatus } from "./pipeline-worker-status";
 * 2. Render <PipelineWorkerStatus /> near the top of the Address Pipeline
 *    tab, above the in-browser pipeline controls.
 * 3. Done — self-contained, no props.
 */
type WorkerStatus = {
  state: "idle" | "running" | "paused" | "stopping";
  total: number;
  completed: number;
  failed: number;
  skipped: number;
  current: string | null;
  startedAt: string | null;
  lastFlushAt: string | null;
  lastError: string | null;
  addressesFile: string | null;
  chainId: string;
  aiSecondPass: boolean;
  delayMs: number;
  pending: number;
  db?: { host: string; port: string; user: string; database: string } | null;
  dbScans?: number | null;
  dbError?: string | null;
};

const WORKER_KEY = "sk-pipeline-worker-url";
const DEFAULT_WORKER = "http://127.0.0.1:8788";

export function PipelineWorkerStatus() {
  const [workerUrl, setWorkerUrl] = useState(DEFAULT_WORKER);
  const [status, setStatus] = useState<WorkerStatus | null>(null);
  const [unreachable, setUnreachable] = useState(false);
  const [addressesFile, setAddressesFile] = useState("");
  const [chainId, setChainId] = useState("ethereum");
  const [aiSecondPass, setAiSecondPass] = useState(false);
  const [delayMs, setDelayMs] = useState(600);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    try {
      const saved = localStorage.getItem(WORKER_KEY);
      if (saved) setWorkerUrl(saved);
    } catch {
      // localStorage unavailable — default stands
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    const fetchStatus = async () => {
      try {
        const res = await fetch(`${workerUrl.replace(/\/$/, "")}/status`, {
          signal: AbortSignal.timeout(5000),
        });
        if (!res.ok) throw new Error(`worker answered ${res.status}`);
        if (!cancelled) {
          setStatus((await res.json()) as WorkerStatus);
          setUnreachable(false);
        }
      } catch {
        if (!cancelled) setUnreachable(true);
      }
    };
    void fetchStatus();
    const t = setInterval(fetchStatus, 5000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, [workerUrl]);

  const saveWorkerUrl = (v: string) => {
    setWorkerUrl(v);
    try {
      localStorage.setItem(WORKER_KEY, v);
    } catch {
      // ignore — persistence is a nicety
    }
  };

  const post = async (path: string, body?: unknown) => {
    setBusy(true);
    setActionError(null);
    try {
      const res = await fetch(`${workerUrl.replace(/\/$/, "")}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(30_000),
      });
      const data = (await res.json().catch(() => ({}))) as { error?: string };
      if (!res.ok) throw new Error(data.error ?? `worker answered ${res.status}`);
      // Refresh status immediately instead of waiting for the next poll.
      const st = await fetch(`${workerUrl.replace(/\/$/, "")}/status`, {
        signal: AbortSignal.timeout(5000),
      });
      if (st.ok) setStatus((await st.json()) as WorkerStatus);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const done = status ? status.completed + status.failed + status.skipped : 0;
  const pct = status && status.total > 0 ? Math.round((done / status.total) * 100) : 0;
  const state = status?.state ?? "idle";

  return (
    <div className="p-3 bg-[#1c1a16] rounded-xl border border-[#3a3428] flex flex-col gap-2 font-mono text-xs">
      <div className="flex items-center gap-1.5 font-bold text-[#e8a54b]">
        <Server className="w-3.5 h-3.5" />
        <span>Headless pipeline worker (Termux — survives browser close)</span>
        {status && (
          <span
            className={`ml-1 px-1.5 py-0.5 rounded text-[10px] uppercase ${
              state === "running"
                ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
                : state === "paused"
                  ? "bg-amber-950 text-amber-300 border border-amber-800"
                  : state === "stopping"
                    ? "bg-amber-950 text-amber-300 border border-amber-800"
                    : "bg-[#12110e] text-[#a39886] border border-[#3a3428]"
            }`}
          >
            {state}
          </span>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <label className="text-[11px] text-[#a39886]">Worker</label>
        <input
          type="text"
          value={workerUrl}
          onChange={(e) => saveWorkerUrl(e.target.value)}
          className="flex-1 min-w-44 bg-[#12110e] border border-[#3a3428] rounded px-2 py-1 text-xs text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
        />
      </div>

      {unreachable && (
        <div className="text-[11px] text-amber-300 bg-amber-950/30 border border-amber-900/50 rounded p-2 leading-relaxed">
          <span className="font-bold">Worker not reachable.</span> Start it in Termux/proot:
          <pre className="mt-1 text-[#f4efe6] whitespace-pre-wrap">bash pipeline-worker/start.sh</pre>
        </div>
      )}

      {status && (
        <>
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-[#a39886]">
            <span>
              Progress: <span className="text-[#f4efe6] font-bold">{done} / {status.total}</span> ({pct}%)
            </span>
            <span>
              Completed: <span className="text-emerald-400">{status.completed}</span>
            </span>
            <span>
              Failed: <span className="text-red-400">{status.failed}</span>
            </span>
            <span>
              Skipped: <span className="text-[#f4efe6]">{status.skipped}</span>
            </span>
            <span>
              Pending flush: <span className="text-[#f4efe6]">{status.pending}</span>
            </span>
          </div>
          <div className="h-2 bg-[#12110e] border border-[#3a3428] rounded overflow-hidden">
            <div
              className="h-full bg-[#e8a54b] transition-all"
              style={{ width: `${pct}%` }}
            />
          </div>
          {status.current && (
            <p className="text-[11px] text-[#a39886] truncate">
              Current: <span className="text-[#f4efe6]">{status.current}</span>
            </p>
          )}
          <p className="text-[11px] text-[#a39886]">
            {status.addressesFile ? `File: ${status.addressesFile} • ` : ""}
            {status.startedAt ? `Started: ${new Date(status.startedAt).toLocaleString()} • ` : ""}
            {status.lastFlushAt ? `Last flush: ${new Date(status.lastFlushAt).toLocaleString()}` : "No flush yet"}
          </p>
          {status.db && (
            <p className="text-[11px] text-[#a39886]">
              DB: <span className="text-[#f4efe6]">{status.db.user}@{status.db.host}:{status.db.port}/{status.db.database}</span>
              {" • "}
              Scans in DB: <span className="text-[#f4efe6]">{status.dbScans ?? "?"}</span>
              {" — if this count and the Supabase dashboard disagree, the dashboard is open on a different project"}
            </p>
          )}
          {status.dbError && (
            <p className="text-[11px] text-red-400 flex items-start gap-1">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              <span>DB: {status.dbError}</span>
            </p>
          )}
          {status.lastError && (
            <p className="text-[11px] text-red-400 flex items-start gap-1">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              <span>{status.lastError}</span>
            </p>
          )}
        </>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <input
          type="text"
          placeholder="Addresses file on the worker machine, e.g. ~/addresses.csv"
          value={addressesFile}
          onChange={(e) => setAddressesFile(e.target.value)}
          disabled={state !== "idle"}
          className="flex-1 min-w-56 bg-[#12110e] border border-[#3a3428] rounded px-2 py-1 text-xs text-[#f4efe6] focus:outline-none focus:border-[#e8a54b] disabled:opacity-50"
        />
        <input
          type="text"
          placeholder="Chain"
          value={chainId}
          onChange={(e) => setChainId(e.target.value)}
          disabled={state !== "idle"}
          className="w-28 bg-[#12110e] border border-[#3a3428] rounded px-2 py-1 text-xs text-[#f4efe6] focus:outline-none focus:border-[#e8a54b] disabled:opacity-50"
        />
        <input
          type="number"
          min={0}
          title="Delay between items (ms)"
          value={delayMs}
          onChange={(e) => setDelayMs(Number(e.target.value))}
          disabled={state !== "idle"}
          className="w-20 bg-[#12110e] border border-[#3a3428] rounded px-2 py-1 text-xs text-[#f4efe6] focus:outline-none focus:border-[#e8a54b] disabled:opacity-50"
        />
        <label className="flex items-center gap-1.5 text-[11px] text-[#a39886]">
          <input
            type="checkbox"
            checked={aiSecondPass}
            onChange={(e) => setAiSecondPass(e.target.checked)}
            disabled={state !== "idle"}
          />
          AI 2nd pass
        </label>
      </div>

      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => post("/start", { addressesFile: addressesFile.trim(), chainId: chainId.trim() || "ethereum", aiSecondPass, delayMs })}
          disabled={busy || state !== "idle" || !addressesFile.trim()}
          className="text-xs px-3 py-1.5 rounded bg-[#e8a54b] text-[#12110e] font-bold flex items-center gap-1.5 hover:bg-[#f0b25e] disabled:opacity-50"
        >
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
          Start worker run
        </button>
        <button
          onClick={() => post("/pause")}
          disabled={busy || state !== "running"}
          className="text-xs px-3 py-1.5 rounded border border-[#3a3428] text-[#f4efe6] flex items-center gap-1.5 hover:border-[#e8a54b] disabled:opacity-50"
        >
          <Pause className="w-3.5 h-3.5" /> Pause
        </button>
        <button
          onClick={() => post("/resume")}
          disabled={busy || state !== "paused"}
          className="text-xs px-3 py-1.5 rounded border border-[#3a3428] text-[#f4efe6] flex items-center gap-1.5 hover:border-[#e8a54b] disabled:opacity-50"
        >
          <Play className="w-3.5 h-3.5" /> Resume
        </button>
        <button
          onClick={() => post("/stop")}
          disabled={busy || state === "idle"}
          className="text-xs px-3 py-1.5 rounded border border-red-900/60 text-red-300 flex items-center gap-1.5 hover:border-red-700 disabled:opacity-50"
        >
          <Square className="w-3.5 h-3.5" /> Stop
        </button>
      </div>

      {actionError && (
        <p className="text-[11px] text-red-400">{actionError}</p>
      )}
    </div>
  );
}
