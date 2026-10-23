import { PocEvidenceBadge } from "@/components/poc-evidence-badge";
import { FpMatchBadge } from "@/components/fp-match-badge";
import { findingPocEvidence } from "@/lib/audit/poc-evidence";
import { SUPPORTED_CHAINS } from "@/lib/audit/address-fetcher";
import { useState, useEffect, useRef, useMemo, useCallback } from "react";
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
  Scale,
  X,
} from "lucide-react";
import {
  getFindingPocRunsFn,
  getFpSignaturesFn,
  getRecentHighSeverityFindingsFn,
  getScan,
  saveComprehensiveScanFn,
  saveFindingPocResultFn,
  setFindingDispositionFn,
  setFpSignatureDecisionFn,
} from "@/lib/scans.functions";
import type { FindingWithScanInfo, FpSignature, StoredScan } from "@/lib/audit/persist.server";
import {
  CHAIN_STEP_ORDER,
  failedAdjudicationOutcome,
  runAdjudicationChain,
  type AdjudicationOutcome,
  type ChainStep,
  type ChainStepState,
} from "@/lib/audit/adjudicate-chain";
import {
  partitionPocAuditFindings,
  type AuditorDisposition,
  type FindingDisposition,
  type PocAuditScope,
} from "@/lib/audit/adjudication";
import { DISPOSITION_CONFIG, DISPOSITION_ORDER } from "@/components/workbench/presentation";
import {
  countExecutableTestFunctions,
  effectivePocStatus,
  ensureExecutablePocTests,
  savedStatusFromRun,
  unadaptedTemplateCheck,
  unadaptedTemplateOutput,
  type SavedPocStatus,
} from "@/lib/audit/poc-outcome";
import {
  createRepairBodyResolver,
  externalTokenCandidate,
  pocAuditReviewPayload,
  type RepairBodyResolution,
} from "@/lib/audit/poc-audit-llm";
import { wrapPocSnippet } from "@/lib/audit/poc-wrap";
import { balanceLabel, nativeSymbol } from "@/lib/audit/balance";
import {
  runPocWithRpcRetries,
  getBackendUrl,
  pocInputDigest,
  checkFoundryBackend,
  isPocCompileError,
  BACKEND_KEY,
  type BackendHealth,
} from "@/lib/audit/foundry-backend";
import { requestAiReview, requestPocRepair } from "@/lib/audit/ai.functions";
import { savePocRun, type PocRunResult } from "@/lib/poc-runs";
import { getStoredSupabaseConfig } from "@/lib/supabase";
import type { PocResult } from "@/lib/audit/types";

interface RecentPocAuditsProps {
  onLoadScanInWorkbench?: (scanId: string) => void;
}

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

// Run result → the status it is saved under. The mapping lives in
// poc-outcome.ts, shared with the adjudication chain: a hollow
// zero-test run saves as "no_tests" and a value-guard skip as
// "skipped" — this function used to fold both into "error", which is
// what polluted the Errors bucket.
function mapStatus(poc: PocResult): SavedPocStatus {
  return savedStatusFromRun({ status: poc.status, logs: poc.logs });
}

/** Pipeline step chips (fetch ✓ / llm ✓ / harness ✓ / saved ✓) plus the
 *  INCOMPLETE marker for a chain that stopped early. */
function ChainStepChips({
  steps,
  outcome,
}: {
  steps?: Partial<Record<ChainStep, ChainStepState | "running">>;
  outcome?: AdjudicationOutcome;
}) {
  const finalSteps = outcome?.steps;
  if (!steps && !finalSteps) return null;
  return (
    <span className="inline-flex items-center gap-1.5 flex-wrap text-[10px] font-mono">
      {CHAIN_STEP_ORDER.map((s) => {
        const state = finalSteps?.[s] ?? steps?.[s];
        return (
          <span
            key={s}
            className={`px-1.5 py-0.5 rounded border capitalize ${
              state === "done"
                ? "border-emerald-800 text-emerald-300"
                : state === "reused"
                  ? "border-sky-800 text-sky-300"
                  : state === "failed"
                    ? "border-red-800 text-red-300"
                    : state === "running"
                      ? "border-[#e8a54b]/50 text-[#e8a54b]"
                      : "border-[#3a3428] text-[#746c60]"
            }`}
          >
            {s}{" "}
            {state === "done"
              ? "✓"
              : state === "reused"
                ? "↺"
                : state === "failed"
                  ? "✗"
                  : state === "running"
                    ? "…"
                    : state === "skipped"
                      ? "–"
                      : "·"}
          </span>
        );
      })}
      {outcome && !outcome.complete && (
        <span className="text-red-400 font-bold">INCOMPLETE — stopped at {outcome.stoppedAt}</span>
      )}
      {outcome?.complete && outcome.kind !== "already_adjudicated" && (
        <span className="text-emerald-400">pipeline complete</span>
      )}
    </span>
  );
}

export function RecentPocAudits({ onLoadScanInWorkbench }: RecentPocAuditsProps) {
  const [findings, setFindings] = useState<FindingWithScanInfo[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<"all" | "critical" | "high">("critical");
  // Presence-only findings (opcode-presence evidence only) are excluded
  // from the actionable scope by default; the toggle includes them
  // deliberately.
  const [showPresenceOnly, setShowPresenceOnly] = useState<boolean>(false);
  const [statusFilter, setStatusFilter] = useState<"all" | "passed" | "failed" | "error" | "no_tests" | "unadapted" | "skipped" | "unrun">("all");
  
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

  // Auditor dispositions (migration 0015), seeded from the feed rows and
  // kept current by local writes. Keyed by finding id.
  const [dispositions, setDispositions] = useState<Record<string, FindingDisposition>>({});
  const [dispositionSavingId, setDispositionSavingId] = useState<string | null>(null);
  const [noteDrafts, setNoteDrafts] = useState<Record<string, string>>({});

  // FP signatures (G7, migration 0017): patterns derived server-side
  // from the false_positive dispositions above. Confirming one only
  // annotates matching findings (the fpMatch chip) — it never
  // suppresses, re-scores, or disposes anything.
  const [fpSignatures, setFpSignatures] = useState<FpSignature[]>([]);
  const [fpSignaturesError, setFpSignaturesError] = useState<string | null>(null);
  const [fpDecisionSavingKey, setFpDecisionSavingKey] = useState<string | null>(null);
  const [showDismissedFp, setShowDismissedFp] = useState<boolean>(false);

  const fetchFpSignatures = useCallback(async () => {
    try {
      setFpSignatures(await getFpSignaturesFn());
      setFpSignaturesError(null);
    } catch (err) {
      console.warn("[kiln] Failed to load FP signatures:", err);
      setFpSignaturesError(
        `FP patterns unavailable: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }, []);

  // One tap records the human's decision on a derived FP pattern. The
  // server row is the decision of record; the local list swaps in the
  // returned row so the panel reflects it without a full reload.
  const handleFpDecision = async (sig: FpSignature, status: "confirmed" | "dismissed") => {
    if (fpDecisionSavingKey) return;
    setFpDecisionSavingKey(sig.key);
    try {
      const saved = await setFpSignatureDecisionFn({ data: { signatureKey: sig.key, status } });
      setFpSignatures((prev) => prev.map((s) => (s.key === saved.key ? saved : s)));
    } catch (err) {
      setFeedbackNotice(
        `FP pattern decision failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    } finally {
      setFpDecisionSavingKey(null);
    }
  };

  // Adjudication chain state per finding + the undisposed queue.
  const [adjudications, setAdjudications] = useState<Record<string, {
    running: boolean;
    notice?: string;
    outcome?: AdjudicationOutcome;
    steps?: Partial<Record<ChainStep, ChainStepState | "running">>;
  }>>({});
  const [isQueueRunning, setIsQueueRunning] = useState<boolean>(false);
  const [queueProgress, setQueueProgress] = useState<{ current: number; total: number; currentTitle?: string } | null>(null);
  const abortQueueRef = useRef<boolean>(false);

  // Full-body source for the direct path's LLM repair/generation calls
  // (workbench parity — see poc-audit-llm.ts). One resolver per page
  // session: its per-scanId cache means AUDIT ALL loads a scan's body
  // once, however many of its findings run.
  const repairBodyResolverRef = useRef<ReturnType<typeof createRepairBodyResolver> | null>(null);
  if (!repairBodyResolverRef.current) {
    repairBodyResolverRef.current = createRepairBodyResolver(async (scanId) => {
      const stored = await getScan({ data: { id: scanId } });
      return stored?.body ?? null;
    });
  }

  // Expanded details for inspection
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [activeCodeTab, setActiveCodeTab] = useState<Record<string, "exploit" | "logs">>({});

  // Backend health state
  const [backendUrl, setBackendUrl] = useState<string>(getBackendUrl());
  const [backendHealth, setBackendHealth] = useState<BackendHealth>(null);
  const [isCheckingBackend, setIsCheckingBackend] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [feedbackNotice, setFeedbackNotice] = useState<string | null>(null);

  // Memoised so the effect below can depend on the function itself rather than
  // re-running on every render (or silently capturing a stale severityFilter).
  const fetchFindings = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await getRecentHighSeverityFindingsFn({
        data: { limit: 100, severityFilter },
      });
      setFindings(data);
      const seeded: Record<string, FindingDisposition> = {};
      for (const f of data) {
        if (f.disposition) {
          seeded[f.id] = {
            findingId: f.id,
            disposition: f.disposition,
            note: f.dispositionNote ?? null,
            updatedAt: f.dispositionUpdatedAt ?? "",
          };
        }
      }
      setDispositions(seeded);
    } catch (err) {
      console.warn("[kiln] Failed to fetch recent findings:", err);
      setFeedbackNotice("Failed to load recent findings from database.");
    } finally {
      setIsLoading(false);
    }
  }, [severityFilter]);

  const checkBackend = useCallback(async () => {
    setIsCheckingBackend(true);
    try {
      const h = await checkFoundryBackend(backendUrl);
      setBackendHealth(h);
    } catch {
      setBackendHealth(null);
    } finally {
      setIsCheckingBackend(false);
    }
  }, [backendUrl]);

  useEffect(() => {
    fetchFindings();
    checkBackend();
    fetchFpSignatures();
  }, [fetchFindings, checkBackend, fetchFpSignatures]);

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

    // LLM calls in this path (generation gate + compile repair) receive
    // the parent scan's FULL stored body — the same context the
    // workbench hands the identical repair prompt (poc-audit-llm.ts).
    // Resolved lazily, only when a call actually happens, and cached
    // per scan by the resolver. If the stored body cannot be loaded the
    // resolver falls back to the finding snippet and says why; that
    // note goes on the run record (snippetFallbackNote), never silent.
    let repairBodyPromise: Promise<RepairBodyResolution> | null = null;
    const getRepairBody = (): Promise<RepairBodyResolution> => {
      if (!repairBodyPromise) {
        repairBodyPromise = repairBodyResolverRef.current!.resolve(
          finding.scanId,
          finding.snippet || finding.exploitSolidity,
        );
      }
      return repairBodyPromise;
    };
    const snippetFallbackNote = async (): Promise<string | null> => {
      if (!repairBodyPromise) return null;
      const resolved = await repairBodyPromise;
      return resolved.source === "snippet" ? (resolved.note ?? null) : null;
    };

    // Generation gate (shared with the adjudication chain — poc-outcome.ts):
    // a PoC with no executable test function can only produce a hollow
    // tests=0 run. One LLM generation attempt; if it still has none, save
    // the outcome as "no_tests" WITHOUT calling the Foundry backend.
    if (countExecutableTestFunctions(testCode) === 0) {
      setExecutingMap((prev) => ({
        ...prev,
        [finding.id]: { running: true, repairing: true, notice: "PoC has no executable test function — asking the LLM to generate one..." },
      }));
    }
    const gate = await ensureExecutablePocTests(testCode, async (instruction) => {
      const repaired = await requestPocRepair({
        data: {
          contractName: finding.contractName || finding.scanLabel || "PoCTarget",
          originalCode: testCode,
          errorLogs: instruction,
          body: (await getRepairBody()).body,
        },
      });
      return repaired?.fixedCode ?? null;
    });
    testCode = gate.testCode;
    if (gate.testCount === 0) {
      const finishedAt = new Date().toISOString();
      const bodyNote = await snippetFallbackNote();
      const displayLogs = `Finding input SHA3-256: ${pocInputDigest(finding.exploitSolidity)}\n${wrapped?.note ? `${wrapped.note}\n` : ""}${bodyNote ? `${bodyNote}\n` : ""}[SmartPoC] Not run — the prepared PoC contains no executable test function, so forge would run 0 tests. ${gate.generationNote ?? ""} Saved as no_tests: a generation gap, not an error and not a verdict on the finding.`;
      try {
        await saveFindingPocResultFn({
          data: {
            findingId: finding.id,
            scanId: finding.scanId,
            status: "no_tests",
            source: testCode,
            output: displayLogs,
            durationMs: 0,
            chainId: finding.chainId ?? "1",
            targetAddress,
            exitCode: null,
            truncated: displayLogs.length > 50000,
          },
        });
        setFindings((prev) =>
          prev.map((f) =>
            f.id === finding.id
              ? { ...f, pocStatus: "no_tests", pocOutput: displayLogs, pocDurationMs: 0, pocRunAt: finishedAt, pocCode: testCode }
              : f
          )
        );
        setExecutingMap((prev) => ({
          ...prev,
          [finding.id]: { running: false, repairing: false, notice: "No executable tests — saved as no-tests (backend not called)" },
        }));
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        setExecutingMap((prev) => ({
          ...prev,
          [finding.id]: { running: false, repairing: false, notice: `Run error: ${errMsg}` },
        }));
      }
      return false;
    }

    // Unadapted-template pre-check (shared with the adjudication chain
    // — poc-outcome.ts): the prepared PoC IS a fallback template whose
    // required TODO constants are still zero, so it would abort on its
    // own precondition and file as a verdict it never earned. Save the
    // outcome as "unadapted" WITHOUT calling the Foundry backend — the
    // same deliberate-non-run shape as the no_tests gate above. An
    // adapted template (constants filled) fails this check and runs.
    const todoCheck = unadaptedTemplateCheck(testCode);
    if (todoCheck) {
      const finishedAt = new Date().toISOString();
      const bodyNote = await snippetFallbackNote();
      const displayLogs = `Finding input SHA3-256: ${pocInputDigest(finding.exploitSolidity)}\n${wrapped?.note ? `${wrapped.note}\n` : ""}${bodyNote ? `${bodyNote}\n` : ""}${unadaptedTemplateOutput(todoCheck.file, todoCheck.unfilled)}`;
      try {
        await saveFindingPocResultFn({
          data: {
            findingId: finding.id,
            scanId: finding.scanId,
            status: "unadapted",
            source: testCode,
            output: displayLogs,
            durationMs: 0,
            chainId: finding.chainId ?? "1",
            targetAddress,
            exitCode: null,
            truncated: displayLogs.length > 50000,
          },
        });
        setFindings((prev) =>
          prev.map((f) =>
            f.id === finding.id
              ? { ...f, pocStatus: "unadapted", pocOutput: displayLogs, pocDurationMs: 0, pocRunAt: finishedAt, pocCode: testCode }
              : f
          )
        );
        setExecutingMap((prev) => ({
          ...prev,
          [finding.id]: { running: false, repairing: false, notice: "Unadapted template — saved as unadapted (backend not called)" },
        }));
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        setExecutingMap((prev) => ({
          ...prev,
          [finding.id]: { running: false, repairing: false, notice: `Run error: ${errMsg}` },
        }));
      }
      return false;
    }

    // POC_TOKEN for token-rescue harnesses (template 46 reads it):
    // resolve the target's external-token candidate from the parent
    // scan's stored valuation — lazily, only when the harness actually
    // references POC_TOKEN, and never fatally (no candidate keeps the
    // template's own-token default, unchanged).
    let tokenAddress: string | undefined;
    if (testCode.includes("POC_TOKEN")) {
      try {
        const storedScan = await getScan({ data: { id: finding.scanId } });
        tokenAddress =
          externalTokenCandidate(storedScan.report, targetAddress || storedScan.targetAddress) ??
          undefined;
      } catch {
        tokenAddress = undefined;
      }
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
        ...(tokenAddress ? { tokenAddress } : {}),
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
              body: (await getRepairBody()).body,
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
              ...(tokenAddress ? { tokenAddress } : {}),
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
      const bodyNote = await snippetFallbackNote();
      const displayLogs = `Finding input SHA3-256: ${pocInputDigest(finding.exploitSolidity)}\n${wrapped?.note ? `${wrapped.note}\n` : ""}${bodyNote ? `${bodyNote}\n` : ""}${rawLogs}`;
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

  // One tap writes (or updates) the auditor disposition of record. The
  // server UPSERTs on finding_id, so re-tapping the same disposition is
  // a no-op and changing it updates the single row.
  const handleSetDisposition = async (
    finding: FindingWithScanInfo,
    disposition: AuditorDisposition,
    note?: string,
  ) => {
    if (dispositionSavingId) return;
    setDispositionSavingId(finding.id);
    try {
      const saved = await setFindingDispositionFn({
        data: {
          findingId: finding.id,
          disposition,
          note: note !== undefined ? note : (dispositions[finding.id]?.note ?? null),
        },
      });
      setDispositions((prev) => ({ ...prev, [finding.id]: saved }));
      setFindings((prev) =>
        prev.map((f) =>
          f.id === finding.id
            ? {
                ...f,
                disposition: saved.disposition,
                dispositionNote: saved.note,
                dispositionUpdatedAt: saved.updatedAt,
              }
            : f,
        ),
      );
    } catch (err) {
      setFeedbackNotice(
        `Disposition save failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    } finally {
      setDispositionSavingId(null);
    }
  };

  // The full adjudication pipeline for one finding: fetch (load the
  // parent scan) → LLM review → Foundry harness → saved verdict +
  // suggested disposition. The chain writes the run; only a human tap
  // on a disposition button writes a disposition.
  const handleAdjudicate = async (finding: FindingWithScanInfo, force = false) => {
    if (adjudications[finding.id]?.running) return;
    setAdjudications((prev) => ({
      ...prev,
      [finding.id]: { running: true, notice: "Loading the parent scan (fetch step)…", steps: {} },
    }));

    let stored: StoredScan;
    try {
      stored = await getScan({ data: { id: finding.scanId } });
    } catch (err) {
      setAdjudications((prev) => ({
        ...prev,
        [finding.id]: {
          running: false,
          outcome: failedAdjudicationOutcome(
            `Could not load the parent scan — the pipeline stopped at the fetch step. ${err instanceof Error ? err.message : String(err)}`,
            "fetch",
          ),
        },
      }));
      return;
    }

    try {
      const outcome = await runAdjudicationChain(
        {
          scanId: finding.scanId,
          finding,
          findings: stored.report.findings,
          contractName: finding.contractName || stored.report.label || "Target",
          body: stored.body,
          targetAddress: finding.targetAddress ?? stored.targetAddress ?? null,
          chainId: finding.chainId ?? stored.chainId ?? null,
          aiReview: stored.aiReview ?? null,
          disposition: dispositions[finding.id] ?? null,
          force,
          // Template 46's POC_TOKEN: the target's most valuable external
          // ERC-20 holding from the stored scan's valuation, when known.
          pocToken: externalTokenCandidate(
            stored.report,
            finding.targetAddress ?? stored.targetAddress ?? null,
          ),
        },
        {
          requestAiReview: async ({ contractName, body, findings: scanFindings }) => {
            const review = await requestAiReview({
              // Workbench parity: the same fourbyte context, derived
              // from the stored scan's report with the same helper the
              // workbench runs over its live report (poc-audit-llm.ts).
              data: pocAuditReviewPayload({
                contractName,
                body,
                findings: scanFindings,
                storedReport: stored.report,
              }),
            });
            return review ?? null;
          },
          persistAiReview: async (review) => {
            await saveComprehensiveScanFn({
              data: {
                id: stored.id,
                label: stored.label,
                report: stored.report,
                body: stored.body,
                targetAddress: stored.targetAddress ?? null,
                chainId: stored.chainId ?? "ethereum",
                compilerVersion: stored.report.inventory.compiler,
                proxyInfo: stored.proxyInfo ?? null,
                probes: stored.probes ?? [],
                aiReview: review,
                triageStates: stored.triageStates ?? null,
                sourceOrigin: "workbench",
                indexToRag: false,
              },
            });
          },
          // The server fn already returns full AdjudicationRunRecord
          // rows (id/status/sourceDigest/output/durationMs/createdAt) —
          // pass them through like the workbench does instead of
          // re-mapping to a subset the dep type rejects.
          listRuns: async (findingId) => getFindingPocRunsFn({ data: { findingId } }),
          runPoc: async ({ address, chainId, testCode, tokenAddress }) => {
            const poc = await runPocWithRpcRetries(backendUrl, {
              address,
              chainId: chainId ?? "ethereum",
              testCode,
              ...(tokenAddress ? { tokenAddress } : {}),
            });
            return {
              status: poc.status,
              logs: poc.logs ?? "",
              durationMs: poc.durationMs ?? 0,
              executedSource: poc.executedSource,
            };
          },
          repairPoc: async ({ contractName, originalCode, errorLogs, body }) => {
            const repaired = await requestPocRepair({
              data: { contractName, originalCode, errorLogs, body },
            });
            return repaired?.fixedCode ?? null;
          },
          isCompileError: (logs) => isPocCompileError(logs),
          saveRun: async (record) => {
            await saveFindingPocResultFn({
              data: {
                findingId: record.findingId,
                scanId: record.scanId,
                status: record.status,
                source: record.source,
                output: record.output,
                durationMs: record.durationMs,
                chainId: record.chainId ?? "1",
                targetAddress: record.targetAddress ?? "",
                exitCode: null,
                truncated: record.output.length > 50000,
              },
            });
          },
          onProgress: (notice) =>
            setAdjudications((prev) => ({
              ...prev,
              [finding.id]: { ...prev[finding.id], running: true, notice },
            })),
          onStep: (stepName, state) =>
            setAdjudications((prev) => ({
              ...prev,
              [finding.id]: {
                ...prev[finding.id],
                steps: { ...prev[finding.id]?.steps, [stepName]: state },
              },
            })),
        },
      );

      setAdjudications((prev) => ({
        ...prev,
        [finding.id]: { running: false, outcome },
      }));

      // Mirror the verdict onto the row, like a manual Run PoC does. The
      // generation gate's no_tests outcome and the pre-check's
      // unadapted outcome never execute (runStep "skipped") but ARE
      // saved — mirror them too when they completed, so the card shows
      // the new status without a refresh.
      if (
        (outcome.runStep === "executed" ||
          outcome.runStep === "reused" ||
          (outcome.verdict === "no_tests" && outcome.complete) ||
          (outcome.verdict === "unadapted" && outcome.complete)) &&
        outcome.verdict
      ) {
        const verdict = outcome.verdict;
        setFindings((prev) =>
          prev.map((f) =>
            f.id === finding.id
              ? {
                  ...f,
                  pocStatus: verdict,
                  pocOutput: outcome.output ?? f.pocOutput,
                  pocCode: outcome.testCode ?? f.pocCode,
                  pocRunAt: new Date().toISOString(),
                }
              : f,
          ),
        );
      }
    } catch (err) {
      setAdjudications((prev) => ({
        ...prev,
        [finding.id]: {
          running: false,
          outcome: failedAdjudicationOutcome(
            `Adjudication failed before completing — nothing was written. ${err instanceof Error ? err.message : String(err)}`,
            "fetch",
          ),
        },
      }));
    }
  };

  // Queue mode: adjudicate every filtered, in-scope finding that has NO
  // disposition yet, sequentially. Each ends at the suggestion state —
  // the queue never writes a disposition.
  const handleAdjudicateAllUndisposed = async () => {
    if (isQueueRunning || isBatchRunning) return;
    const targets = filteredFindings.filter((f) => !dispositions[f.id]);
    if (targets.length === 0) return;
    abortQueueRef.current = false;
    setIsQueueRunning(true);
    setQueueProgress({ current: 0, total: targets.length });

    for (let i = 0; i < targets.length; i++) {
      if (abortQueueRef.current) {
        setFeedbackNotice("Adjudication queue cancelled.");
        break;
      }
      const item = targets[i];
      setQueueProgress({ current: i + 1, total: targets.length, currentTitle: item.title });
      await handleAdjudicate(item, false);
    }

    setIsQueueRunning(false);
    setQueueProgress(null);
    if (!abortQueueRef.current) {
      setFeedbackNotice(
        `Adjudication queue finished: ${targets.length} finding(s) processed. Suggestions are on each card — nothing was confirmed automatically.`,
      );
      setTimeout(() => setFeedbackNotice(null), 6000);
    }
  };

  const handleStopQueue = () => {
    abortQueueRef.current = true;
    setIsQueueRunning(false);
    setQueueProgress(null);
  };

  // Filter findings
  const evidenceById = useMemo(() => new Map(findings.map(f => [f.id, findingPocEvidence(f)])), [findings]);

  // "Actually critical" scope, applied at READ time (stored severities
  // predate the detector demotions): criticals — highs only once the
  // severity filter widens past "critical" — minus uncorroborated
  // bytecode-presence-only findings, which join the actionable set only
  // when the header toggle includes them deliberately. The list, AUDIT
  // ALL and the adjudication queue all consume this scoped set.
  const auditScope: PocAuditScope = severityFilter === "critical" ? "critical" : "critical_and_high";
  const scopePartition = partitionPocAuditFindings(findings, auditScope);
  const actionableFindings = showPresenceOnly
    ? [...scopePartition.eligible, ...scopePartition.presenceOnlyExcluded]
    : scopePartition.eligible;

  const filteredFindings = actionableFindings.filter((f) => {
    // Effective status: rows saved under the old vocabulary report
    // tests=0 runs and value-guard skips as "error"; effectivePocStatus
    // reclassifies them on read, so the filters match the counters.
    const effStatus = effectivePocStatus(f.pocStatus, f.pocOutput);
    if (statusFilter === "passed" && evidenceById.get(f.id)?.stage !== "reproduced") return false;
    if (statusFilter === "failed" && effStatus !== "failed") return false;
    if (statusFilter === "error" && effStatus !== "error") return false;
    if (statusFilter === "no_tests" && effStatus !== "no_tests") return false;
    if (statusFilter === "unadapted" && effStatus !== "unadapted") return false;
    if (statusFilter === "skipped" && effStatus !== "skipped") return false;
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
  // Outcome-kind counters over EFFECTIVE statuses: real errors only in
  // the error count; zero-test runs and value-guard skips (including
  // historical rows saved as "error") count as their own kinds.
  const unverifiedCount = findings.filter((f) => effectivePocStatus(f.pocStatus, f.pocOutput) === "failed").length;
  const errorCount = findings.filter((f) => effectivePocStatus(f.pocStatus, f.pocOutput) === "error").length;
  const noTestsCount = findings.filter((f) => effectivePocStatus(f.pocStatus, f.pocOutput) === "no_tests").length;
  const unadaptedCount = findings.filter((f) => effectivePocStatus(f.pocStatus, f.pocOutput) === "unadapted").length;
  const skippedCount = findings.filter((f) => effectivePocStatus(f.pocStatus, f.pocOutput) === "skipped").length;
  const undisposedFiltered = filteredFindings.filter((f) => !dispositions[f.id]);
  const runningAdjudication = Object.values(adjudications).find((a) => a.running);

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
                  {severityFilter === "critical" ? "Actually-Critical Scope" : "Critical & High DB Scope"}
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
                disabled={isLoading || filteredFindings.length === 0 || isQueueRunning}
                className="px-4 py-1.5 rounded-lg bg-gradient-to-r from-[#e8a54b] to-[#d97706] hover:brightness-110 text-[#12110e] text-xs font-bold font-mono tracking-wide flex items-center gap-1.5 shadow-md shadow-[#e8a54b]/20 transition-all active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>AUDIT ALL RECOMMENDED POCS ({filteredFindings.length})</span>
              </button>
            )}

            {isQueueRunning ? (
              <button
                onClick={handleStopQueue}
                className="px-4 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-bold font-mono tracking-wide flex items-center gap-1.5 shadow transition-all active:scale-95"
              >
                <StopCircle className="w-4 h-4 fill-current" />
                <span>STOP QUEUE</span>
              </button>
            ) : (
              <button
                onClick={handleAdjudicateAllUndisposed}
                disabled={isLoading || isBatchRunning || undisposedFiltered.length === 0}
                className="px-4 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#e8a54b]/40 text-xs font-bold font-mono tracking-wide text-[#e8a54b] flex items-center gap-1.5 transition-all active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed"
                title="Run the full pipeline (fetch → LLM → harness → saved verdict) for every filtered finding with no disposition yet. Suggestions only — nothing is confirmed automatically."
              >
                <Scale className="w-3.5 h-3.5" />
                <span>ADJUDICATE ALL UNDISPOSED ({undisposedFiltered.length})</span>
              </button>
            )}
          </div>
        </div>

        {/* Adjudication Queue Progress Bar (with live per-step state) */}
        {queueProgress && (
          <div className="bg-[#12110e] border border-[#3a3428] rounded-xl p-3 flex flex-col gap-2 animate-fadeIn">
            <div className="flex items-center justify-between text-xs font-mono gap-3 flex-wrap">
              <span className="text-[#e8a54b] flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                Adjudicating finding {queueProgress.current} of {queueProgress.total}: {queueProgress.currentTitle}
              </span>
              <span className="text-[#a39886]">
                {Math.round((queueProgress.current / queueProgress.total) * 100)}%
              </span>
            </div>
            {runningAdjudication && (
              <div className="flex items-center gap-2 flex-wrap">
                <ChainStepChips steps={runningAdjudication.steps} />
                {runningAdjudication.notice && (
                  <span className="text-[11px] font-mono text-[#a39886]">{runningAdjudication.notice}</span>
                )}
              </div>
            )}
            <div className="w-full h-1.5 bg-[#26231c] rounded-full overflow-hidden">
              <div
                className="h-full bg-[#e8a54b] transition-all duration-300"
                style={{ width: `${(queueProgress.current / queueProgress.total) * 100}%` }}
              />
            </div>
          </div>
        )}

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
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
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

          <div className="bg-[#12110e] border border-[#2d281f] rounded-xl p-3">
            <span className="text-[10px] font-mono uppercase text-[#746c60] block">No tests</span>
            <div className="text-xl font-bold font-mono text-[#e8a54b] mt-1 flex items-center gap-1.5">
              <FileCode className="w-4 h-4" />
              {noTestsCount}
            </div>
          </div>

          <div className="bg-[#12110e] border border-[#2d281f] rounded-xl p-3">
            <span className="text-[10px] font-mono uppercase text-[#746c60] block">Unadapted</span>
            <div className="text-xl font-bold font-mono text-[#e8a54b] mt-1 flex items-center gap-1.5">
              <FileCode className="w-4 h-4" />
              {unadaptedCount}
            </div>
          </div>

          <div className="bg-[#12110e] border border-[#2d281f] rounded-xl p-3">
            <span className="text-[10px] font-mono uppercase text-[#746c60] block">Skipped (no value)</span>
            <div className="text-xl font-bold font-mono text-[#a39886] mt-1 flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4" />
              {skippedCount}
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
            {([
              ["all", "all"],
              ["passed", "passed"],
              ["failed", "failed"],
              ["error", "error"],
              ["no_tests", "no tests"],
              ["unadapted", "unadapted"],
              ["skipped", "skipped"],
              ["unrun", "unrun"],
            ] as const).map(([st, label]) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2 py-0.5 rounded capitalize transition-colors ${
                  statusFilter === st
                    ? "bg-[#e8a54b] text-[#12110e] font-bold"
                    : "text-[#a39886] hover:text-[#f4efe6]"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Presence-only scope visibility: bytecode findings whose only
          evidence is opcode presence are out of the actionable scope by
          default (read-time rule — stored severities are not rewritten). */}
      <div className="flex items-center gap-3 flex-wrap text-[11px] font-mono text-[#a39886] px-1">
        <span>
          <span className="text-[#f4efe6] font-bold">{scopePartition.presenceOnlyExcluded.length}</span>{" "}
          presence-only excluded
          <span className="text-[#746c60]"> (opcode-presence evidence only — not actually critical)</span>
        </span>
        <button
          onClick={() => setShowPresenceOnly((v) => !v)}
          className={`px-2 py-0.5 rounded border transition-colors ${
            showPresenceOnly
              ? "bg-[#e8a54b] text-[#12110e] font-bold border-[#e8a54b]"
              : "bg-[#26231c] border-[#3a3428] text-[#a39886] hover:text-[#f4efe6]"
          }`}
        >
          {showPresenceOnly ? "Presence-only included" : "Include presence-only"}
        </button>
        {!showPresenceOnly && scopePartition.presenceOnlyExcluded.length > 0 && (
          <span className="text-[#746c60]">toggle to adjudicate them deliberately</span>
        )}
      </div>

      {/* FP patterns (G7): candidates derived from false_positive
          dispositions. Confirming a pattern ONLY annotates matching
          findings — it never suppresses, re-scores, or disposes one. */}
      {(fpSignatures.length > 0 || fpSignaturesError) && (
        <div className="bg-[#1c1a16] border border-[#3a3428] rounded-2xl p-4 sm:p-5 flex flex-col gap-3">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <span className="text-[11px] font-mono text-[#a39886] uppercase tracking-wider">
              FP patterns — derived from your false_positive dispositions
            </span>
            <span className="text-[10px] font-mono text-[#746c60]">
              annotation only · confirming never suppresses, re-scores, or disposes a finding
            </span>
          </div>
          {fpSignaturesError && (
            <span className="text-xs font-mono text-red-400">{fpSignaturesError}</span>
          )}
          {fpSignatures
            .filter((s) => s.status === "candidate")
            .map((sig) => (
              <div
                key={sig.key}
                className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-lg bg-[#26231c]/50 border border-[#3a3428]"
              >
                <div className="flex flex-col gap-0.5 min-w-0">
                  <span className="text-xs font-mono text-[#f4efe6]">
                    <span className="font-bold">{sig.detector}</span>
                    {" · "}
                    {sig.titlePattern}
                  </span>
                  <span className="text-[10px] font-mono text-[#a39886]">
                    {sig.evidenceCount} false_positive dispositions across {sig.scanCount} scans
                    {" · "}fn: {sig.locationFn ?? "any"}
                    {" · "}evidence: {sig.snippetClass ?? "any"}
                    {sig.sampleTitles.length > 0 && <> · e.g. “{sig.sampleTitles[0]}”</>}
                  </span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => handleFpDecision(sig, "confirmed")}
                    disabled={fpDecisionSavingKey !== null}
                    className="px-2.5 py-1 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-violet-500/40 text-[11px] font-mono font-semibold text-violet-300 flex items-center gap-1 transition-colors disabled:opacity-50"
                    title="Confirm: findings matching this shape get a visible 'matches confirmed FP pattern' note. Nothing is suppressed or re-scored."
                  >
                    {fpDecisionSavingKey === sig.key ? (
                      <Loader2 className="w-3 h-3 animate-spin" />
                    ) : (
                      <Check className="w-3 h-3" />
                    )}
                    <span>Confirm pattern</span>
                  </button>
                  <button
                    onClick={() => handleFpDecision(sig, "dismissed")}
                    disabled={fpDecisionSavingKey !== null}
                    className="px-2.5 py-1 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[11px] font-mono text-[#a39886] flex items-center gap-1 transition-colors disabled:opacity-50"
                    title="Dismiss: this pattern is never proposed again, however much matching FP evidence accrues."
                  >
                    <X className="w-3 h-3" />
                    <span>Dismiss</span>
                  </button>
                </div>
              </div>
            ))}
          {fpSignatures
            .filter((s) => s.status === "confirmed")
            .map((sig) => (
              <div
                key={sig.key}
                className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 px-3 py-2 rounded-lg border border-violet-500/20"
              >
                <span className="text-[11px] font-mono text-violet-300 min-w-0">
                  ✓ confirmed · <span className="font-bold">{sig.detector}</span> · {sig.titlePattern}
                  <span className="text-[#a39886]">
                    {" "}({sig.evidenceCount} FPs / {sig.scanCount} scans · fn: {sig.locationFn ?? "any"} · evidence: {sig.snippetClass ?? "any"})
                  </span>
                </span>
                <button
                  onClick={() => handleFpDecision(sig, "dismissed")}
                  disabled={fpDecisionSavingKey !== null}
                  className="px-2 py-0.5 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[10px] font-mono text-[#a39886] shrink-0 transition-colors disabled:opacity-50"
                  title="Revoke this pattern: stop annotating and never re-propose it."
                >
                  Revoke
                </button>
              </div>
            ))}
          {fpSignatures.some((s) => s.status === "dismissed") && (
            <>
              <button
                onClick={() => setShowDismissedFp((v) => !v)}
                className="self-start text-[10px] font-mono text-[#746c60] hover:text-[#a39886] transition-colors"
              >
                {showDismissedFp ? "Hide" : "Show"}{" "}
                {fpSignatures.filter((s) => s.status === "dismissed").length} dismissed pattern(s) — never re-proposed
              </button>
              {showDismissedFp &&
                fpSignatures
                  .filter((s) => s.status === "dismissed")
                  .map((sig) => (
                    <div
                      key={sig.key}
                      className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 px-3 py-2 rounded-lg border border-[#3a3428] opacity-60"
                    >
                      <span className="text-[11px] font-mono text-[#a39886] min-w-0">
                        dismissed · <span className="font-bold">{sig.detector}</span> · {sig.titlePattern}
                      </span>
                      <button
                        onClick={() => handleFpDecision(sig, "confirmed")}
                        disabled={fpDecisionSavingKey !== null}
                        className="px-2 py-0.5 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[10px] font-mono text-[#a39886] shrink-0 transition-colors disabled:opacity-50"
                        title="Undo the dismissal and confirm this pattern instead."
                      >
                        Confirm instead
                      </button>
                    </div>
                  ))}
            </>
          )}
        </div>
      )}

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
            const adjudication = adjudications[finding.id];
            const disposition = dispositions[finding.id];
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
                        <span
                          className={(() => {
                            const bal = balanceLabel(finding.balanceWei, nativeSymbol(finding.chainId ?? "ethereum"));
                            return bal === null ? "text-[#746c60]" : bal.startsWith("0 ") ? "text-red-400" : "text-[#e8c07d]";
                          })()}
                          title="Native coin balance of the target at analysis time"
                        >
                          {balanceLabel(finding.balanceWei, nativeSymbol(finding.chainId ?? "ethereum")) ?? "balance n/a"}
                        </span>
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

                    {disposition && (
                      <span
                        className={`px-2 py-1 rounded text-[10px] font-mono font-bold border ${DISPOSITION_CONFIG[disposition.disposition].badge}`}
                        title={disposition.note ?? "Auditor disposition of record"}
                      >
                        ⚖ {DISPOSITION_CONFIG[disposition.disposition].label}
                      </span>
                    )}

                    {finding.fpMatch && <FpMatchBadge match={finding.fpMatch} />}

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

                    {/* Full adjudication pipeline for this finding */}
                    <button
                      onClick={() => handleAdjudicate(finding, false)}
                      disabled={adjudication?.running || isBatchRunning || isQueueRunning}
                      className="px-2.5 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#e8a54b]/40 text-xs font-mono font-semibold text-[#e8a54b] flex items-center gap-1 transition-colors disabled:opacity-50"
                      title="Fetch scan → LLM review → Foundry harness → saved verdict + suggested disposition (reuses work already done)"
                    >
                      {adjudication?.running ? (
                        <Loader2 className="w-3 h-3 animate-spin" />
                      ) : (
                        <Scale className="w-3 h-3" />
                      )}
                      <span>Adjudicate</span>
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

                {/* Adjudication progress + suggestion (one-tap accept) */}
                {adjudication && (adjudication.running || adjudication.outcome) && (
                  <div className="flex flex-col gap-1.5 bg-[#12110e] px-2.5 py-2 rounded-md border border-[#3a3428]">
                    <div className="flex items-center gap-2 flex-wrap">
                      <ChainStepChips steps={adjudication.steps} outcome={adjudication.outcome} />
                      {adjudication.running && adjudication.notice && (
                        <span className="text-[11px] font-mono text-[#e8a54b] flex items-center gap-1.5">
                          <Loader2 className="w-3 h-3 animate-spin shrink-0" />
                          {adjudication.notice}
                        </span>
                      )}
                    </div>
                    {adjudication.outcome && (
                      <>
                        <span className="text-[11px] font-mono text-[#a39886]">
                          {adjudication.outcome.message}
                          {adjudication.outcome.saveError
                            ? ` (verdict save failed: ${adjudication.outcome.saveError})`
                            : ""}
                        </span>
                        {adjudication.outcome.kind !== "already_adjudicated" && (
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="text-[10px] font-mono uppercase tracking-wider text-[#746c60]">
                              Suggested:
                            </span>
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${DISPOSITION_CONFIG[adjudication.outcome.suggestion].badge}`}
                            >
                              {DISPOSITION_CONFIG[adjudication.outcome.suggestion].label}
                            </span>
                            <button
                              onClick={() =>
                                handleSetDisposition(finding, adjudication.outcome!.suggestion)
                              }
                              disabled={dispositionSavingId !== null}
                              className="px-2 py-0.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-[10px] font-mono font-bold transition-colors disabled:opacity-50"
                            >
                              {dispositionSavingId === finding.id ? "Saving…" : "✓ Accept"}
                            </button>
                            <button
                              onClick={() =>
                                setAdjudications((prev) => {
                                  const next = { ...prev };
                                  delete next[finding.id];
                                  return next;
                                })
                              }
                              className="px-2 py-0.5 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[10px] font-mono text-[#a39886] transition-colors"
                            >
                              Dismiss
                            </button>
                            <button
                              onClick={() => handleAdjudicate(finding, true)}
                              disabled={adjudication.running || isQueueRunning}
                              className="px-2 py-0.5 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[10px] font-mono text-[#a39886] transition-colors disabled:opacity-50"
                              title="Re-run the whole chain, ignoring the idempotency skips"
                            >
                              ↺ Redo
                            </button>
                          </div>
                        )}
                      </>
                    )}
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
                    {/* Auditor disposition of record */}
                    <div className="flex flex-col gap-2 bg-[#12110e] border border-[#2d281f] rounded-xl p-3">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-[10px] font-mono uppercase tracking-wider text-[#746c60]">
                          Auditor disposition
                        </span>
                        {disposition ? (
                          <>
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${DISPOSITION_CONFIG[disposition.disposition].badge}`}
                            >
                              {DISPOSITION_CONFIG[disposition.disposition].label}
                            </span>
                            <span className="text-[10px] font-mono text-[#746c60]">
                              set {new Date(disposition.updatedAt).toLocaleString()}
                            </span>
                          </>
                        ) : (
                          <span className="text-[10px] font-mono text-[#746c60]">not set</span>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {DISPOSITION_ORDER.map((d) => (
                          <button
                            key={d}
                            onClick={() =>
                              handleSetDisposition(finding, d, noteDrafts[finding.id])
                            }
                            disabled={dispositionSavingId !== null}
                            className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-semibold border transition-all disabled:opacity-50 ${
                              disposition?.disposition === d
                                ? DISPOSITION_CONFIG[d].badge + " ring-1 ring-current"
                                : "bg-[#26231c] border-[#3a3428] text-[#a39886] hover:text-[#f4efe6]"
                            }`}
                          >
                            {dispositionSavingId === finding.id
                              ? "Saving…"
                              : DISPOSITION_CONFIG[d].label}
                          </button>
                        ))}
                        <input
                          type="text"
                          value={noteDrafts[finding.id] ?? disposition?.note ?? ""}
                          onChange={(e) =>
                            setNoteDrafts((prev) => ({ ...prev, [finding.id]: e.target.value }))
                          }
                          placeholder="Optional note — saved with the next disposition tap"
                          className="flex-1 min-w-52 bg-[#1c1a16] border border-[#3a3428] rounded-lg px-2 py-1 text-[11px] font-mono text-[#f4efe6] placeholder-[#746c60] focus:outline-none focus:border-[#e8a54b]"
                        />
                      </div>
                    </div>

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

