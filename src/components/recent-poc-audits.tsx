import { PocEvidenceBadge } from "@/components/poc-evidence-badge";
import { findingPocEvidence } from "@/lib/audit/poc-evidence";
import { SUPPORTED_CHAINS } from "@/lib/audit/address-fetcher";
import { useState, useEffect, useRef, useMemo } from "react";
import {
  ShieldAlert,
  Play,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Loader2,
  FileCode,
  Terminal,
  ExternalLink,
  Copy,
  Check,
  Search,
  Wand2,
  ChevronDown,
  ChevronUp,
  StopCircle,
} from "lucide-react";
import {
  getRecentHighSeverityFindingsFn,
  saveFindingPocResultFn,
} from "@/lib/scans.functions";
import type { FindingWithScanInfo } from "@/lib/audit/persist.server";
import { wrapPocSnippet } from "@/lib/audit/poc-wrap";
import {
  runPocWithRpcRetries,
  getBackendUrl,
  pocInputDigest,
  checkFoundryBackend,
  isPocCompileError,
  BACKEND_KEY,
  type BackendHealth,
} from "@/lib/audit/foundry-backend";
import { requestPocRepair } from "@/lib/audit/ai.functions";
import { savePocRun, type PocRunResult } from "@/lib/poc-runs";
import { getStoredSupabaseConfig } from "@/lib/supabase";
import type { PocResult } from "@/lib/audit/types";

interface RecentPocAuditsProps {
  onLoadScanInWorkbench?: (scanId: string) => void;
}

const NO_TESTS_RE = /no tests (match|found)|ran 0 tests|0 passed;\s*0 failed/i;

function generateRunId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  const bytes = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function mapStatus(poc: PocResult): "passed" | "failed" | "error" {
  if (poc.status === "passed" && NO_TESTS_RE.test(poc.logs ?? "")) return "error";
  if (poc.status === "passed") return "passed";
  if (poc.status === "failed") return "failed";
  return "error";
}

export function RecentPocAudits({ onLoadScanInWorkbench }: RecentPocAuditsProps) {
  const [findings, setFindings] = useState<FindingWithScanInfo[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<"all" | "critical" | "high">("all");
  const [statusFilter, setStatusFilter] = useState<"all" | "passed" | "failed" | "error" | "unrun">("all");
  
  // Execution state per finding
  const [executingMap, setExecutingMap] = useState<Record<string, {
    running: boolean;
    repairing: boolean;
    notice?: string;
  }>>({});
  
  // Batch running state
  const [isBatchRunning, setIsBatchRunning] = useState<boolean>(false);
  const [batchProgress, setBatchProgress] = useState<{ current: number; total: number; currentTitle?: string } | null>(null);
  const abortBatchRef = useRef<boolean>(false);

  // Expanded details for inspection
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [activeCodeTab, setActiveCodeTab] = useState<Record<string, "exploit" | "logs">>({});

  // Backend health state
  const [backendUrl, setBackendUrl] = useState<string>(getBackendUrl());
  const [backendHealth, setBackendHealth] = useState<BackendHealth>(null);
  const [isCheckingBackend, setIsCheckingBackend] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [feedbackNotice, setFeedbackNotice] = useState<string | null>(null);

  const fetchFindings = async () => {
    setIsLoading(true);
    try {
      const data = await getRecentHighSeverityFindingsFn({
        data: { limit: 100, severityFilter },
      });
      setFindings(data);
    } catch (err) {
      console.warn("[kiln] Failed to fetch recent findings:", err);
      setFeedbackNotice("Failed to load recent findings from database.");
    } finally {
      setIsLoading(false);
    }
  };

  const checkBackend = async () => {
    setIsCheckingBackend(true);
    try {
      const h = await checkFoundryBackend(backendUrl);
      setBackendHealth(h);
    } catch {
      setBackendHealth(null);
    } finally {
      setIsCheckingBackend(false);
    }
  };

  useEffect(() => {
    fetchFindings();
    checkBackend();
  }, [severityFilter]);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Run a single finding's recommended PoC, optionally repairing on compile error
  const executeFindingPoc = async (finding: FindingWithScanInfo, autoRepair = true): Promise<boolean> => {
    setExecutingMap((prev) => ({
      ...prev,
      [finding.id]: { running: true, repairing: false, notice: "Preparing test harness..." },
    }));

    const startedAt = new Date().toISOString();
    const targetAddress = finding.targetAddress || "";
    
    // Prepare test code: wrap if it's an attack contract snippet
    let testCode = finding.exploitSolidity;
    const wrapped = wrapPocSnippet(finding.exploitSolidity);
    if (wrapped) {
      testCode = wrapped.testFile;
    }

    try {
      setExecutingMap((prev) => ({
        ...prev,
        [finding.id]: { running: true, repairing: false, notice: "Executing on Foundry fork (auto-retrying candidate RPCs)..." },
      }));

      let poc = await runPocWithRpcRetries(backendUrl, {
        address: targetAddress,
        chainId: finding.chainId ?? "ethereum",
        testCode,
        onProgress: (p) => {
          setExecutingMap((prev) => ({
            ...prev,
            [finding.id]: {
              running: true,
              repairing: false,
              notice: `Testing with RPC ${p.attempt}/${p.total} (${p.rpcUrl.slice(0, 30)}...)...`,
            },
          }));
        },
      });

      // If compile error and autoRepair is enabled, call LLM repair
      if (autoRepair && poc.status === "error" && isPocCompileError(poc.logs ?? "")) {
        setExecutingMap((prev) => ({
          ...prev,
          [finding.id]: { running: true, repairing: true, notice: "Solc compile error detected — repairing PoC with LLM..." },
        }));

        try {
          const repaired = await requestPocRepair({
            data: {
              contractName: finding.contractName || finding.scanLabel || "PoCTarget",
              originalCode: testCode,
              errorLogs: poc.logs ?? "",
              body: finding.snippet || finding.exploitSolidity,
            },
          });
          if (repaired && repaired.fixedCode) {
            testCode = repaired.fixedCode;
            setExecutingMap((prev) => ({
              ...prev,
              [finding.id]: { running: true, repairing: false, notice: "Re-executing repaired PoC on fork..." },
            }));
            poc = await runPocWithRpcRetries(backendUrl, {
              address: targetAddress,
        chainId: finding.chainId ?? "ethereum",
              testCode,
              onProgress: (p) => {
                setExecutingMap((prev) => ({
                  ...prev,
                  [finding.id]: {
                    running: true,
                    repairing: false,
                    notice: `Re-executing with RPC ${p.attempt}/${p.total}...`,
                  },
                }));
              },
            });
          }
        } catch (repairErr) {
          console.warn("[kiln] LLM repair failed:", repairErr);
        }
      }

      const finishedAt = new Date().toISOString();
      const status = mapStatus(poc);
      const rawLogs = poc.logs ?? "";
      const displayLogs = `Finding input SHA3-256: ${pocInputDigest(finding.exploitSolidity)}\n${wrapped?.note ? `${wrapped.note}\n` : ""}${rawLogs}`;
      const durationMs = poc.durationMs ?? 0;
      const runId = generateRunId();

      // 1. Save to local Postgres / PGLite database
      await saveFindingPocResultFn({
        data: {
          findingId: finding.id,
          scanId: finding.scanId,
          status,
          source: testCode,
          output: displayLogs,
          durationMs,
          chainId: finding.chainId ?? "1",
          targetAddress,
          exitCode: null,
          truncated: displayLogs.length > 50000,
        },
      });

      // 2. Also save to Supabase poc_runs table if configured
      try {
        const sbConfig = getStoredSupabaseConfig();
        if (sbConfig.enabled) {
          const sbRunResult: PocRunResult = {
            id: runId,
            source: testCode,
            status,
            startedAt,
            finishedAt,
            durationMs,
            chainId: SUPPORTED_CHAINS.find(c => c.id === finding.chainId || String(c.chainId) === finding.chainId)?.chainId ?? 1,
            exitCode: null,
            output: displayLogs.slice(0, 100000),
            truncated: displayLogs.length > 100000,
          };
          await savePocRun(sbRunResult, sbConfig);
        }
      } catch (sbErr) {
        console.warn("[kiln] Supabase PoC run sync error:", sbErr);
      }

      // Update in-memory state
      setFindings((prev) =>
        prev.map((f) =>
          f.id === finding.id
            ? {
                ...f,
                pocStatus: status,
                pocOutput: displayLogs,
                pocDurationMs: durationMs,
                pocRunAt: finishedAt,
                pocCode: testCode,
              }
            : f
        )
      );

      setExecutingMap((prev) => ({
        ...prev,
        [finding.id]: { running: false, repairing: false, notice: `Complete (${status}) — saved to DB` },
      }));

      return status === "passed";
    } catch (err) {
      console.error("[kiln] Execution failed:", err);
      const errMsg = err instanceof Error ? err.message : String(err);
      
      setExecutingMap((prev) => ({
        ...prev,
        [finding.id]: { running: false, repairing: false, notice: `Run error: ${errMsg}` },
      }));

      // Still record failure to DB
      try {
        await saveFindingPocResultFn({
          data: {
            findingId: finding.id,
            scanId: finding.scanId,
            status: "error",
            source: testCode,
            output: `Execution error: ${errMsg}`,
            durationMs: 0,
            chainId: finding.chainId ?? "1",
            targetAddress,
            exitCode: null,
            truncated: false,
          },
        });

        setFindings((prev) =>
          prev.map((f) =>
            f.id === finding.id
              ? {
                  ...f,
                  pocStatus: "error",
                  pocOutput: `Execution error: ${errMsg}`,
                  pocDurationMs: 0,
                  pocRunAt: new Date().toISOString(),
                  pocCode: testCode,
                }
              : f
          )
        );
      } catch {
        // ignore secondary save failure
      }

      return false;
    }
  };

  // Run all currently filtered findings in sequence
  const handleRunAllPocs = async () => {
    if (isBatchRunning) return;
    abortBatchRef.current = false;
    setIsBatchRunning(true);

    const targetList = filteredFindings.filter((f) => f.exploitSolidity.trim().length > 0);
    setBatchProgress({ current: 0, total: targetList.length });

    for (let i = 0; i < targetList.length; i++) {
      if (abortBatchRef.current) {
        setFeedbackNotice("Batch PoC execution cancelled.");
        break;
      }
      const item = targetList[i];
      setBatchProgress({ current: i + 1, total: targetList.length, currentTitle: item.title });
      await executeFindingPoc(item, true);
    }

    setIsBatchRunning(false);
    setBatchProgress(null);
    setFeedbackNotice("Batch PoC execution completed and results saved to DB.");
    setTimeout(() => setFeedbackNotice(null), 4000);
  };

  const handleStopBatch = () => {
    abortBatchRef.current = true;
    setIsBatchRunning(false);
    setBatchProgress(null);
  };

  // Filter findings
  const evidenceById = useMemo(() => new Map(findings.map(f => [f.id, findingPocEvidence(f)])), [findings]);

  const filteredFindings = findings.filter((f) => {
    if (statusFilter === "passed" && evidenceById.get(f.id)?.stage !== "reproduced") return false;
    if (statusFilter === "failed" && f.pocStatus !== "failed") return false;
    if (statusFilter === "error" && f.pocStatus !== "error") return false;
    if (statusFilter === "unrun" && f.pocStatus) return false;

    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      f.title.toLowerCase().includes(q) ||
      f.summary.toLowerCase().includes(q) ||
      (f.swc && f.swc.toLowerCase().includes(q)) ||
      (f.contractName && f.contractName.toLowerCase().includes(q)) ||
      (f.scanLabel && f.scanLabel.toLowerCase().includes(q)) ||
      (f.targetAddress && f.targetAddress.toLowerCase().includes(q))
    );
  });

  // Calculate stats
  const totalCount = findings.length;
  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const reproducedCount = findings.filter((f) => evidenceById.get(f.id)?.stage === "reproduced").length;
  const unverifiedCount = findings.filter((f) => f.pocStatus === "failed").length;
  const errorCount = findings.filter((f) => f.pocStatus === "error").length;

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto p-4 sm:p-6 animate-fadeIn">
      {/* Top Banner & Stat Cards */}
      <div className="bg-[#1c1a16] border border-[#3a3428] rounded-2xl p-5 shadow-lg flex flex-col gap-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#e8a54b]/10 border border-[#e8a54b]/30 flex items-center justify-center shrink-0">
              <ShieldAlert className="w-5 h-5 text-[#e8a54b]" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-lg font-bold text-[#f4efe6]">
                  Recent Findings PoC Auditor
                </h2>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-amber-500/10 text-[#e8a54b] border border-amber-500/30">
                  Critical & High DB Scope
                </span>
              </div>
              <p className="text-xs text-[#a39886] mt-0.5">
                Automated Foundry fork execution & verification for recent vulnerabilities. Tests reproduce on chain fork state and outcomes are saved to DB.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={fetchFindings}
              disabled={isLoading || isBatchRunning}
              className="px-3 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-xs font-mono text-[#f4efe6] flex items-center gap-1.5 transition-colors"
              title="Refresh findings from database"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-[#e8a54b] ${isLoading ? "animate-spin" : ""}`} />
              <span>Refresh</span>
            </button>

            {isBatchRunning ? (
              <button
                onClick={handleStopBatch}
                className="px-4 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-bold font-mono tracking-wide flex items-center gap-1.5 shadow transition-all active:scale-95"
              >
                <StopCircle className="w-4 h-4 fill-current" />
                <span>STOP BATCH</span>
              </button>
            ) : (
              <button
                onClick={handleRunAllPocs}
                disabled={isLoading || filteredFindings.length === 0}
                className="px-4 py-1.5 rounded-lg bg-gradient-to-r from-[#e8a54b] to-[#d97706] hover:brightness-110 text-[#12110e] text-xs font-bold font-mono tracking-wide flex items-center gap-1.5 shadow-md shadow-[#e8a54b]/20 transition-all active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>AUDIT ALL RECOMMENDED POCS ({filteredFindings.length})</span>
              </button>
            )}
          </div>
        </div>

        {/* Batch Progress Bar */}
        {batchProgress && (
          <div className="bg-[#12110e] border border-[#3a3428] rounded-xl p-3 flex flex-col gap-2 animate-fadeIn">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-[#e8a54b] flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                Auditing finding {batchProgress.current} of {batchProgress.total}: {batchProgress.currentTitle}
              </span>
              <span className="text-[#a39886]">
                {Math.round((batchProgress.current / batchProgress.total) * 100)}%
              </span>
            </div>
            <div className="w-full h-1.5 bg-[#26231c] rounded-full overflow-hidden">
              <div
                className="h-full bg-[#e8a54b] transition-all duration-300"
                style={{ width: `${(batchProgress.current / batchProgress.total) * 100}%` }}
              />
            </div>
          </div>
        )}

        {/* Backend Status Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono bg-[#12110e] border border-[#2d281f] rounded-xl px-3.5 py-2">
          <div className="flex items-center gap-2">
            <span className="text-[#746c60]">Foundry Backend:</span>
            <input
              type="text"
              value={backendUrl}
              onChange={(e) => {
                setBackendUrl(e.target.value);
                try {
                  localStorage.setItem(BACKEND_KEY, e.target.value);
                } catch {
                  // ignore
                }
              }}
              className="bg-[#1c1a16] border border-[#3a3428] rounded px-2 py-0.5 text-[#f4efe6] text-xs w-48 sm:w-60 focus:outline-none focus:border-[#e8a54b]"
            />
            <button
              onClick={checkBackend}
              disabled={isCheckingBackend}
              className="text-[#a39886] hover:text-[#f4efe6]"
              title="Test backend connection"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isCheckingBackend ? "animate-spin text-[#e8a54b]" : ""}`} />
            </button>
          </div>

          <div className="flex items-center gap-2">
            {backendHealth?.ok ? (
              <span className="inline-flex items-center gap-1 text-emerald-400">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Forge Ready (Loopback)
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-[#e8a54b]" title="Local Foundry backend (Termux or local node server). If unreachable, PoCs test in simulation or report backend unreachable.">
                <AlertTriangle className="w-3.5 h-3.5 text-[#e8a54b]" />
                Backend: {backendUrl}
              </span>
            )}
          </div>
        </div>

        {/* Metric Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="bg-[#12110e] border border-[#2d281f] rounded-xl p-3">
            <span className="text-[10px] font-mono uppercase text-[#746c60] block">Critical / High Findings</span>
            <div className="text-xl font-bold font-mono text-[#f4efe6] mt-1 flex items-baseline gap-2">
              {totalCount}
              <span className="text-xs font-normal text-[#a39886]">
                ({criticalCount} crit, {highCount} high)
              </span>
            </div>
          </div>

          <div className="bg-[#12110e] border border-[#2d281f] rounded-xl p-3">
            <span className="text-[10px] font-mono uppercase text-emerald-400/80 block">Reproduced assertions</span>
            <div className="text-xl font-bold font-mono text-emerald-400 mt-1 flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4" />
              {reproducedCount}
            </div>
          </div>

          <div className="bg-[#12110e] border border-[#2d281f] rounded-xl p-3">
            <span className="text-[10px] font-mono uppercase text-amber-400/80 block">Not reproduced</span>
            <div className="text-xl font-bold font-mono text-amber-400 mt-1 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4" />
              {unverifiedCount}
            </div>
          </div>

          <div className="bg-[#12110e] border border-[#2d281f] rounded-xl p-3">
            <span className="text-[10px] font-mono uppercase text-[#746c60] block">Errors / Needs Repair</span>
            <div className="text-xl font-bold font-mono text-red-400 mt-1 flex items-center gap-1.5">
              <XCircle className="w-4 h-4" />
              {errorCount}
            </div>
          </div>
        </div>
      </div>

      {feedbackNotice && (
        <div className="px-4 py-2 bg-emerald-950/80 border border-emerald-800 text-emerald-300 text-xs font-mono rounded-xl flex items-center justify-between animate-fadeIn">
          <span>{feedbackNotice}</span>
          <button onClick={() => setFeedbackNotice(null)} className="text-emerald-400 hover:text-white">
            ✕
          </button>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-[#1c1a16] border border-[#3a3428] rounded-xl p-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-[#746c60]" />
          <input
            type="text"
            placeholder="Search by contract name, title, address (0x...), or SWC..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#12110e] border border-[#3a3428] rounded-lg pl-9 pr-4 py-1.5 text-xs text-[#f4efe6] placeholder-[#746c60] focus:outline-none focus:border-[#e8a54b]"
          />
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1 bg-[#12110e] border border-[#3a3428] rounded-lg p-1 text-xs font-mono">
            <span className="text-[11px] text-[#746c60] px-1.5">Severity:</span>
            {(["all", "critical", "high"] as const).map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-0.5 rounded capitalize transition-colors ${
                  severityFilter === sev
                    ? "bg-[#e8a54b] text-[#12110e] font-bold"
                    : "text-[#a39886] hover:text-[#f4efe6]"
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1 bg-[#12110e] border border-[#3a3428] rounded-lg p-1 text-xs font-mono">
            <span className="text-[11px] text-[#746c60] px-1.5">PoC Status:</span>
            {(["all", "passed", "failed", "error", "unrun"] as const).map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2 py-0.5 rounded capitalize transition-colors ${
                  statusFilter === st
                    ? "bg-[#e8a54b] text-[#12110e] font-bold"
                    : "text-[#a39886] hover:text-[#f4efe6]"
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Findings List */}
      <div className="flex flex-col gap-4">
        {isLoading ? (
          <div className="p-12 text-center flex flex-col items-center justify-center gap-3 bg-[#1c1a16] border border-[#3a3428] rounded-2xl">
            <Loader2 className="w-8 h-8 text-[#e8a54b] animate-spin" />
            <span className="text-xs font-mono text-[#a39886]">
              Loading recent high & critical findings from database...
            </span>
          </div>
        ) : filteredFindings.length === 0 ? (
          <div className="p-12 text-center flex flex-col items-center justify-center gap-2 bg-[#1c1a16] border border-[#3a3428] rounded-2xl">
            <FileCode className="w-8 h-8 text-[#746c60]" />
            <span className="text-sm font-semibold text-[#f4efe6]">No findings matched your criteria</span>
            <span className="text-xs text-[#a39886]">
              Run an audit in the Workbench or adjust your filter query.
            </span>
          </div>
        ) : (
          filteredFindings.map((finding) => {
            const isExpanded = expandedFindingId === finding.id;
            const execution = executingMap[finding.id];
            const currentCodeTab = activeCodeTab[finding.id] || "exploit";

            return (
              <div
                key={finding.id}
                className="bg-[#1c1a16] border border-[#3a3428] hover:border-[#4d4536] rounded-2xl p-4 sm:p-5 shadow-sm transition-all flex flex-col gap-3"
              >
                {/* Finding Header */}
                <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
                  <div className="flex items-start gap-3">
                    <span
                      className={`px-2.5 py-1 rounded text-[10px] font-mono font-bold uppercase tracking-wider shrink-0 border ${
                        finding.severity === "critical"
                          ? "bg-red-950 text-red-300 border-red-700/60 shadow-sm shadow-red-900/30"
                          : "bg-amber-950 text-amber-300 border-amber-700/60"
                      }`}
                    >
                      {finding.severity}
                    </span>

                    <div className="flex flex-col gap-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <h3 className="text-sm font-bold text-[#f4efe6]">
                          {finding.title}
                        </h3>
                        {finding.swc && (
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#26231c] text-[#e8a54b] border border-[#3a3428]">
                            SWC-{finding.swc}
                          </span>
                        )}
                        <span className="text-[10px] font-mono text-[#746c60]">
                          Detector: {finding.detector}
                        </span>
                      </div>

                      <div className="flex items-center gap-2 text-xs text-[#a39886] font-mono flex-wrap">
                        <span className="text-[#f4efe6] font-semibold">
                          {finding.contractName || finding.scanLabel}
                        </span>
                        {finding.targetAddress && (
                          <>
                            <span>•</span>
                            <span className="text-[#e8a54b]">{finding.targetAddress}</span>
                            <button
                              onClick={() => copyToClipboard(finding.targetAddress!, `addr-${finding.id}`)}
                              className="text-[#746c60] hover:text-[#f4efe6]"
                              title="Copy Address"
                            >
                              {copiedKey === `addr-${finding.id}` ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </>
                        )}
                        <span>•</span>
                        <span className="text-[#746c60]">
                          Audited: {new Date(finding.scanCreatedAt).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Right side: PoC status badge & action buttons */}
                  <div className="flex items-center gap-2 shrink-0 flex-wrap">
                    <PocEvidenceBadge evidence={evidenceById.get(finding.id)!} />

                    {/* Run Single PoC Button */}
                    <button
                      onClick={() => executeFindingPoc(finding, true)}
                      disabled={execution?.running || isBatchRunning}
                      className="px-3 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-xs font-mono font-medium text-[#f4efe6] flex items-center gap-1.5 transition-colors disabled:opacity-50"
                      title="Run recommended exploit on Foundry fork"
                    >
                      {execution?.running ? (
                        <Loader2 className="w-3.5 h-3.5 text-[#e8a54b] animate-spin" />
                      ) : (
                        <Play className="w-3.5 h-3.5 text-[#e8a54b]" />
                      )}
                      <span>Run PoC</span>
                    </button>

                    {/* LLM Repair & Run button */}
                    <button
                      onClick={() => executeFindingPoc(finding, true)}
                      disabled={execution?.running || isBatchRunning}
                      className="px-2.5 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-xs font-mono text-[#e8a54b] flex items-center gap-1 transition-colors disabled:opacity-50"
                      title="Repair with LLM and re-run"
                    >
                      <Wand2 className="w-3 h-3" />
                      <span>Repair</span>
                    </button>

                    {/* Open in workbench */}
                    {onLoadScanInWorkbench && (
                      <button
                        onClick={() => onLoadScanInWorkbench(finding.scanId)}
                        className="px-2.5 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-xs font-mono text-[#a39886] hover:text-[#f4efe6] flex items-center gap-1 transition-colors"
                        title="Load contract in Workbench"
                      >
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    )}

                    {/* Expand/Collapse Toggle */}
                    <button
                      onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                      className="p-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] text-[#a39886] hover:text-[#f4efe6] transition-colors"
                    >
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Finding Summary */}
                <p className="text-xs text-[#a39886] line-clamp-2 leading-relaxed">
                  {finding.summary}
                </p>

                {/* Live execution status feedback */}
                {execution?.notice && (
                  <div className="text-[11px] font-mono text-[#e8a54b] flex items-center gap-1.5 bg-[#12110e] px-2.5 py-1 rounded-md border border-[#3a3428]">
                    <Loader2 className="w-3 h-3 animate-spin shrink-0" />
                    <span>{execution.notice}</span>
                  </div>
                )}

                {/* Metadata & Durations footer */}
                <div className="flex items-center justify-between text-[11px] font-mono text-[#746c60] pt-1 border-t border-[#26231c]">
                  <div className="flex items-center gap-3">
                    {finding.pocDurationMs !== undefined && finding.pocDurationMs !== null && (
                      <span>Duration: {finding.pocDurationMs}ms</span>
                    )}
                    {finding.pocRunAt && (
                      <span>Last Run: {new Date(finding.pocRunAt).toLocaleTimeString()}</span>
                    )}
                  </div>
                  <button
                    onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                    className="text-[#a39886] hover:text-[#e8a54b] flex items-center gap-1"
                  >
                    <span>{isExpanded ? "Hide Code & Logs" : "View Recommended PoC & Logs"}</span>
                  </button>
                </div>

                {/* Expanded Inspection Drawer */}
                {isExpanded && (
                  <div className="mt-3 pt-3 border-t border-[#3a3428] flex flex-col gap-3 animate-fadeIn">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1 bg-[#12110e] border border-[#3a3428] rounded-lg p-0.5 text-xs font-mono">
                        <button
                          onClick={() => setActiveCodeTab((prev) => ({ ...prev, [finding.id]: "exploit" }))}
                          className={`px-3 py-1 rounded flex items-center gap-1.5 transition-colors ${
                            currentCodeTab === "exploit"
                              ? "bg-[#e8a54b] text-[#12110e] font-bold"
                              : "text-[#a39886] hover:text-[#f4efe6]"
                          }`}
                        >
                          <FileCode className="w-3.5 h-3.5" />
                          <span>Recommended PoC Attack</span>
                        </button>
                        <button
                          onClick={() => setActiveCodeTab((prev) => ({ ...prev, [finding.id]: "logs" }))}
                          className={`px-3 py-1 rounded flex items-center gap-1.5 transition-colors ${
                            currentCodeTab === "logs"
                              ? "bg-[#e8a54b] text-[#12110e] font-bold"
                              : "text-[#a39886] hover:text-[#f4efe6]"
                          }`}
                        >
                          <Terminal className="w-3.5 h-3.5" />
                          <span>Foundry Test Output & Logs</span>
                        </button>
                      </div>

                      <button
                        onClick={() =>
                          copyToClipboard(
                            currentCodeTab === "exploit"
                              ? (finding.pocCode || finding.exploitSolidity)
                              : (finding.pocOutput || "No logs available"),
                            `code-${finding.id}`
                          )
                        }
                        className="px-2.5 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-xs font-mono text-[#a39886] hover:text-[#f4efe6] flex items-center gap-1 transition-colors"
                      >
                        {copiedKey === `code-${finding.id}` ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-400" />
                            <span>Copied!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Copy</span>
                          </>
                        )}
                      </button>
                    </div>

                    {currentCodeTab === "exploit" ? (
                      <div className="relative">
                        <pre className="p-4 bg-[#12110e] border border-[#2d281f] rounded-xl text-xs font-mono text-[#f4efe6] overflow-x-auto max-h-96 leading-relaxed">
                          {finding.pocCode || finding.exploitSolidity}
                        </pre>
                      </div>
                    ) : (
                      <div className="relative">
                        <pre className="p-4 bg-[#12110e] border border-[#2d281f] rounded-xl text-xs font-mono text-[#e8a54b] overflow-x-auto max-h-96 leading-relaxed">
                          {finding.pocOutput || "No PoC logs recorded yet. Click 'Run PoC' to execute against chain fork."}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

