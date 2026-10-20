import type { Dispatch, SetStateAction } from "react";
import { SUPPORTED_CHAINS, } from "@/lib/audit/address-fetcher";
import type { SupabaseConfig } from "@/lib/supabase";
import { Play, Pause, RotateCcw, Database, Server, Check, X, AlertTriangle, Loader2, Sliders, RefreshCw } from "lucide-react";

type Setter<T> = Dispatch<SetStateAction<T>>;
interface PipelineControlsProps {
  displayChainId: string;
  handleNetworkChange: (chainId: string) => void;
  isRunning: boolean;
  setIsSupabaseModalOpen: Setter<boolean>;
  setIsDbWiringModalOpen: Setter<boolean>;
  supabaseCfg: SupabaseConfig;
  actionNotice: { ok: boolean; msg: string } | null;
  setActionNotice: Setter<{ ok: boolean; msg: string } | null>;
  startPipeline: () => Promise<void>;
  pausePipeline: () => void;
  isPausing: boolean;
  total: number;
  completed: number;
  failed: number;
  pending: number;
  totalCrit: number;
  totalHigh: number;
  percent: number;
  unsynced: number;
  retryFailed: () => void;
  handleLoadNewBatch: () => void;
  handleResumeSupabase: () => Promise<void>;
  isResumingSupabase: boolean;
  delayMs: number;
  setDelayMs: Setter<number>;
  aiSecondPass: boolean;
  setAiSecondPass: Setter<boolean>;
  dbSyncStats: { totalFlushed: number; pendingCount: number; isFlushing: boolean; lastError: string | null };
  pendingWriteCount: number;
  checkpointError: string | null;
  flushDbBuffer: () => Promise<void>;
}

export function PipelineControls({
  displayChainId,
  handleNetworkChange,
  isRunning,
  setIsSupabaseModalOpen,
  setIsDbWiringModalOpen,
  supabaseCfg,
  actionNotice,
  setActionNotice,
  startPipeline,
  pausePipeline,
  isPausing,
  total,
  completed,
  failed,
  pending,
  totalCrit,
  totalHigh,
  percent,
  unsynced,
  retryFailed,
  handleLoadNewBatch,
  handleResumeSupabase,
  isResumingSupabase,
  delayMs,
  setDelayMs,
  aiSecondPass,
  setAiSecondPass,
  dbSyncStats,
  pendingWriteCount,
  checkpointError,
  flushDbBuffer
}: PipelineControlsProps) {
  return (
    <>
      {/* Top Batch Header & Pipeline Stats */}
      <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-5 shadow-sm flex flex-col gap-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <span className="p-1.5 rounded-lg bg-[#3a2c14] border border-[#e8a54b]/40 text-[#e8a54b]">
                <Sliders className="w-4 h-4" />
              </span>
              <h2 className="text-base font-bold text-[#f4efe6]">EVM Address Pipeline Processor</h2>
            </div>
            <p className="text-xs text-[#a39886] mt-1">
              Feed raw contract addresses, pull verified bytecode/source from public RPC & Sourcify, and process batch queues one-by-one.
            </p>
          </div>

          {/* Target Chain Selector & Supabase Indicator */}
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            {/* Chain Selector */}
            <div className="flex items-center gap-1.5 bg-[#26231c] px-3 py-1.5 rounded-lg border border-[#3a3428]">
              <span className="text-[#a39886] text-[11px]">Network:</span>
              <select
                value={displayChainId}
                onChange={(e) => handleNetworkChange(e.target.value)}
                disabled={isRunning}
                className="bg-transparent border-none text-[#e8a54b] font-bold focus:outline-none cursor-pointer"
              >
                {displayChainId === "mixed" && <option value="mixed" disabled>Mixed network queue</option>}
                {SUPPORTED_CHAINS.map((c) => (
                  <option key={c.id} value={c.id} className="bg-[#1c1a16] text-[#f4efe6]">
                    {c.name} (Chain {c.chainId})
                  </option>
                ))}
              </select>
            </div>

            {/* Supabase Status Button */}
            <button
              onClick={() => setIsSupabaseModalOpen(true)}
              className={`px-3 py-1.5 rounded-lg border flex items-center gap-1.5 transition-colors ${
                supabaseCfg.enabled
                  ? "bg-emerald-950/30 border-emerald-700/60 text-emerald-300"
                  : "bg-[#26231c] border-[#3a3428] text-[#a39886] hover:text-[#f4efe6]"
              }`}
            >
              <Database className="w-3.5 h-3.5 text-[#e8a54b]" />
              <span>{supabaseCfg.enabled ? "Supabase Sync: ON" : "Supabase: Config"}</span>
            </button>

            {/* Wire Supabase Postgres DB Button */}
            <button
              onClick={() => setIsDbWiringModalOpen(true)}
              className="px-3 py-1.5 rounded-lg border border-[#3a3428] bg-[#26231c] hover:bg-[#3a3428] text-[#e8a54b] flex items-center gap-1.5 transition-colors"
              title="Wire direct Supabase PostgreSQL database connection"
            >
              <Server className="w-3.5 h-3.5 text-[#e8a54b]" />
              <span>Wire Supabase DB</span>
            </button>
          </div>
        </div>

        {/* Action Notice Notification */}
        {actionNotice && (
          <div
            className={`p-3 rounded-lg border text-xs font-mono flex items-center justify-between transition-all animate-fadeIn ${
              actionNotice.ok
                ? "bg-emerald-950/70 border-emerald-700/60 text-emerald-300"
                : "bg-red-950/70 border-red-700/60 text-red-300"
            }`}
          >
            <div className="flex items-center gap-2">
              {actionNotice.ok ? (
                <Check className="w-4 h-4 text-emerald-400 shrink-0" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              )}
              <span>{actionNotice.msg}</span>
            </div>
            <button
              onClick={() => setActionNotice(null)}
              className="p-1 text-[#a39886] hover:text-white rounded"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Pipeline Control Toolbar & Progress */}
        <div className="bg-[#26231c] border border-[#3a3428] rounded-lg p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-4">
          {/* Main Action Buttons */}
          <div className="flex flex-wrap items-center gap-2">
            {!isRunning ? (
              <button
                onClick={startPipeline}
                disabled={total === 0 || (completed === total && unsynced === 0)}
                className="px-4 py-2 rounded-lg bg-gradient-to-r from-[#e8a54b] to-[#d97706] text-[#12110e] text-xs font-bold font-mono tracking-wide flex items-center gap-1.5 shadow-md shadow-[#e8a54b]/20 transition-all active:scale-95 disabled:opacity-50"
              >
                <Play className="w-4 h-4 fill-current" />
                <span>{completed > 0 && completed < total ? "RESUME PIPELINE" : "START PIPELINE"}</span>
              </button>
            ) : (
              <button
                onClick={pausePipeline}
                disabled={isPausing}
                className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-bold font-mono tracking-wide flex items-center gap-1.5 shadow transition-all active:scale-95 disabled:opacity-50"
              >
                <Pause className="w-4 h-4 fill-current" />
                <span>{isPausing ? "PAUSING..." : "PAUSE"}</span>
              </button>
            )}

            {failed > 0 && !isRunning && (
              <button
                onClick={retryFailed}
                className="px-3 py-2 rounded-lg bg-[#1c1a16] hover:bg-[#322d24] border border-amber-800/60 text-xs font-mono text-amber-400 flex items-center gap-1.5 transition-colors"
                title="Reset all failed addresses back to pending"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Retry Failed ({failed})</span>
              </button>
            )}

            <button
              onClick={handleLoadNewBatch}
              className="px-3 py-2 rounded-lg bg-[#1c1a16] hover:bg-[#322d24] border border-[#3a3428] text-xs font-mono text-[#f4efe6] flex items-center gap-1.5 transition-colors"
              title="Parse new input list and reset queue"
            >
              <RotateCcw className="w-3.5 h-3.5 text-[#e8a54b]" />
              <span>New Batch</span>
            </button>

            <button
              onClick={handleResumeSupabase}
              disabled={isResumingSupabase || isRunning}
              className="px-3 py-2 rounded-lg bg-[#1c1a16] hover:bg-[#322d24] border border-[#3a3428] text-xs font-mono text-[#e8a54b] flex items-center gap-1.5 transition-colors disabled:opacity-50"
              title="Fetch previous audits stored in Supabase PostgreSQL & REST"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isResumingSupabase ? "animate-spin text-[#e8a54b]" : ""}`} />
              <span>{isResumingSupabase ? "Resuming..." : "Resume Supabase DB"}</span>
            </button>

            {/* Delay setting */}
            <div className="flex items-center gap-1 text-[11px] font-mono text-[#a39886] pl-2 border-l border-[#3a3428]">
              <span>Delay:</span>
              <select
                value={delayMs}
                onChange={(e) => setDelayMs(Number(e.target.value))}
                className="bg-[#1c1a16] border border-[#3a3428] rounded px-1.5 py-1 text-[#f4efe6] focus:outline-none"
              >
                <option value={300}>300ms</option>
                <option value={600}>600ms (Safe)</option>
                <option value={1200}>1.2s</option>
                <option value={2000}>2.0s</option>
              </select>
            </div>

            {/* OpenRouter AI second pass (opt-in, 1 LLM call per address) */}
            <label
              className="flex items-center gap-1.5 text-[11px] font-mono text-[#a39886] pl-2 border-l border-[#3a3428] cursor-pointer"
              title="Run the OpenRouter AI second pass before saving (1 LLM call per address). Slower; off by default."
            >
              <input
                type="checkbox"
                checked={aiSecondPass}
                onChange={(e) => setAiSecondPass(e.target.checked)}
                disabled={isRunning}
                className="accent-[#e8a54b]"
              />
              <span>AI 2nd pass</span>
            </label>
          </div>

          {/* Quick Metrics Bar */}
          <div className="flex items-center gap-3 text-xs font-mono">
            <div className="flex items-center gap-1.5 text-[#f4efe6]">
              <span className="text-[#a39886]">Progress:</span>
              <span className="font-bold">
                {completed} / {total}
              </span>
              <span className="text-[#746c60]">({percent}%)</span>
              {pending > 0 && <span className="text-yellow-400 text-[11px]">({pending} left)</span>}
              {failed > 0 && <span className="text-red-400 text-[11px]">({failed} failed)</span>}
            </div>

            <div className="w-px h-5 bg-[#3a3428]" />

            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded bg-red-950/60 text-red-400 border border-red-800 text-[11px]">
                Crit: {totalCrit}
              </span>
              <span className="px-2 py-0.5 rounded bg-amber-950/60 text-amber-400 border border-amber-800 text-[11px]">
                High: {totalHigh}
              </span>
            </div>
          </div>
        </div>

        {/* Animated Progress Bar */}
        <div className="w-full bg-[#12110e] h-2 rounded-full overflow-hidden border border-[#3a3428]">
          <div
            className="h-full bg-gradient-to-r from-[#e8a54b] to-emerald-400 transition-all duration-300"
            style={{ width: `${percent}%` }}
          />
        </div>

        {/* DB Sync & Async Batch Engine Status Strip */}
        <div className="flex items-center justify-between bg-[#191713] border border-[#3a3428] rounded-lg px-3 py-2 text-xs font-mono">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="flex items-center gap-1.5 text-[#e8a54b] font-bold">
              <Database className="w-3.5 h-3.5" />
              <span>DB Batch Engine:</span>
            </span>
            <span className="text-[#a39886]">
              {dbSyncStats.totalFlushed.toLocaleString()} records written to Supabase DB
            </span>
            <span className="text-[#746c60]">•</span>
            {dbSyncStats.isFlushing ? (
              <span className="text-yellow-400 flex items-center gap-1">
                <Loader2 className="w-3 h-3 animate-spin" />
                Flushing batch to DB...
              </span>
            ) : pendingWriteCount > 0 ? (
              <span className="text-[#e8a54b]">
                {pendingWriteCount} records buffered
              </span>
            ) : dbSyncStats.totalFlushed === 0 ? (
              <span className="text-[#a39886]">
                No records written yet
              </span>
            ) : (
              <span className="text-emerald-400 flex items-center gap-1">
                <Check className="w-3 h-3" />
                All records synced
              </span>
            )}
            {(dbSyncStats.lastError || checkpointError) && (
              <span className="text-red-400 text-[11px] truncate max-w-xs" title={dbSyncStats.lastError || checkpointError || undefined}>
                (Warning: {dbSyncStats.lastError || checkpointError})
              </span>
            )}
          </div>

          {pendingWriteCount > 0 && !dbSyncStats.isFlushing && (
            <button
              onClick={() => flushDbBuffer()}
              className="px-2.5 py-0.5 rounded bg-[#3a2c14] hover:bg-[#e8a54b] text-[#e8a54b] hover:text-[#12110e] border border-[#e8a54b]/30 text-[11px] font-bold transition-all"
            >
              Flush Buffer ({pendingWriteCount})
            </button>
          )}
        </div>
      </div>

    </>
  );
}
