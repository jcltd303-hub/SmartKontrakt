import { classifyPocEvidence } from "@/lib/audit/poc-evidence";
import { downloadFile } from "@/lib/download-file";
import { SUPPORTED_CHAINS, analyzeAddress, isValidEvmAddress } from "@/lib/audit/address-fetcher";
import { attachResnetToReport } from "@/lib/audit/resnet-attach";
import { runResnetBrowser } from "@/lib/image-ml/run-resnet-browser";
import type { AiSecurityReview } from "@/lib/audit/ai-review.server";
import { requestAiReview, requestDeepAgentRound, requestPocRepair } from "@/lib/audit/ai.functions";
import { fullDisassembly, looksLikeBytecode } from "@/lib/audit/bytecode";
import type { DeepAgentHypothesis, DeepAgentPriorResult } from "@/lib/audit/deep-agent.server";
import { analyzeInput } from "@/lib/audit/engine";
import {
  getBackendUrl,
  pocInputDigest,
  isPocCompileError,
  runPocWithRpcRetries,
} from "@/lib/audit/foundry-backend";
import { applyFourbyteResults, fourbyteResultsFromReport } from "@/lib/audit/fourbyte";
import { resolveFourbyte } from "@/lib/audit/fourbyte.functions";
import {
  applyInteractiveEdit,
  applyInteractiveLoadError,
  applyWorkbenchPrefill,
  beginInteractiveLoad,
  initialInteractiveSource,
  settleInteractiveLoad,
  type InteractiveSourceState,
} from "@/lib/audit/interactive-source";
import type { ScanSummary, StoredScan } from "@/lib/audit/persist.server";
import { selectPocFallbacks } from "@/lib/audit/poc-fallbacks";
import { externalTokenCandidate } from "@/lib/audit/poc-audit-llm";
import {
  hasUnadaptedEvidence,
  unadaptedTemplateCheck,
  unadaptedTemplateOutput,
} from "@/lib/audit/poc-outcome";
import { wrapPocSnippetWithReason } from "@/lib/audit/poc-wrap";
import { detectProxyArchitecture, type ProxyAnalysis } from "@/lib/audit/proxy-resolver";
import type { RagChunk } from "@/lib/audit/rag.server";
import { type Sample } from "@/lib/audit/samples";
import { probeContractInterfaces, type CallProbeResult } from "@/lib/audit/simulator";
import type { Finding, PocResult, Report } from "@/lib/audit/types";
import { savePocRun, type PocRunResult } from "@/lib/poc-runs";
import {
  failedAdjudicationOutcome,
  runAdjudicationChain,
  type AdjudicationOutcome,
  type ChainStep,
  type ChainStepState,
} from "@/lib/audit/adjudicate-chain";
import type {
  AuditorDisposition,
  FindingDisposition,
} from "@/lib/audit/adjudication";
import {
  getBuildInfoFn,
  getDbInfo,
  getFindingDispositionsFn,
  getFindingPocRunsFn,
  getScan,
  queryRagKnowledgebaseFn,
  saveComprehensiveScanFn,
  saveFindingPocResultFn,
  setFindingDispositionFn,
} from "@/lib/scans.functions";
import { getStoredSupabaseConfig } from "@/lib/supabase";
import { useEffect, useMemo, useRef, useState } from "react";
import { defaultSample } from "./presentation";
import { filterFindings, getRiskColor } from "./selectors";

// One controller owns audit state and async orchestration across all workbench modes.
export function useWorkbenchController(initialScans: ScanSummary[]) {
  // Mode state: Single audit vs Batch address pipeline vs Local DB Records vs RAG Knowledgebase
  const [workbenchMode, setWorkbenchMode] = useState<
    "audit" | "pipeline" | "records" | "rag" | "interactive" | "poc-audits"
  >("audit");

  // Single address input state
  const [singleAddress, setSingleAddress] = useState<string>("");
  const [singleAddressChain, setSingleAddressChain] = useState<string>("ethereum");
  const [isFetchingAddress, setIsFetchingAddress] = useState<boolean>(false);
  const [addressFetchError, setAddressFetchError] = useState<string | null>(null);
  // The address the current contractBody was loaded for (single-address
  // fetch, stored scan, pipeline inspect) — null whenever the body did
  // not come from an address load. The Interactive tab's prefill trusts
  // only this pairing, never the bare address field, so a typed-but-
  // never-fetched address can't dress the sample/pasted body up as that
  // contract's source.
  const [bodyLoadedForAddress, setBodyLoadedForAddress] = useState<string | null>(null);

  // Input state
  const [selectedSampleId, setSelectedSampleId] = useState<string>("relic");
  const [contractBody, setContractBodyRaw] = useState<string>(defaultSample.body);
  const [contractLabel, setContractLabel] = useState<string>(defaultSample.label);
  // External body replacement (editor typing/clear, RAG hand-off): the
  // body no longer provably belongs to the address it was loaded for.
  // Internal load paths use setContractBodyRaw + setBodyLoadedForAddress.
  const setContractBody = (body: string) => {
    setContractBodyRaw(body);
    setBodyLoadedForAddress(null);
  };

  // Interactive Audit & PoC source-box state, lifted here so it survives
  // mode switches and the prefill can protect user edits (the rules live
  // in lib/audit/interactive-source.ts).
  const [interactiveSource, setInteractiveSource] = useState<InteractiveSourceState>(() =>
    initialInteractiveSource(),
  );

  // Analysis state initialized synchronously for identical SSR & Client hydration
  const [report, setReport] = useState<Report>(() =>
    analyzeInput(defaultSample.body, defaultSample.label),
  );
  const [activeTab, setActiveTab] = useState<
    "findings" | "surface" | "bytecode" | "ai" | "probe" | "report" | "history" | "walkthrough"
  >("findings");
  const [bytecodeSubView, setBytecodeSubView] = useState<"stream" | "cfg">("stream");

  // Advanced analysis state
  const [proxyInfo, setProxyInfo] = useState<ProxyAnalysis | null>(null);
  const [probes, setProbes] = useState<CallProbeResult[]>([]);
  const [isProbing, setIsProbing] = useState<boolean>(false);
  const [aiReview, setAiReview] = useState<AiSecurityReview | null>(null);
  const [pocResult, setPocResult] = useState<PocResult | null>(null);
  const [pocRunning, setPocRunning] = useState(false);
  const [pocSaved, setPocSaved] = useState(false);
  // Per-finding PoC runs (Run button on each finding's Attack Contract
  // block, under findings). One run at a time across all findings:
  // findingPocRunLockRef guards the race, and every Run button disables
  // while any run is in flight.
  type FindingPocRun = {
    running: boolean;
    result: PocRunResult | null; // set on terminal result; null while running
    save: "idle" | "saving" | "saved" | "failed" | "not-configured";
    saveError: string | null;
  };
  const [findingPocRuns, setFindingPocRuns] = useState<Record<string, FindingPocRun>>({});
  const findingPocRunLockRef = useRef(false);
  const findingPocRunning = Object.values(findingPocRuns).some((r) => r.running);
  const [savedScanId, setSavedScanId] = useState<string | null>(null);
  const [isLoadingAi, setIsLoadingAi] = useState<boolean>(false);
  // Deep Agent state — agentic exploit search (see deep-agent.server.ts).
  const [deepAgentRunning, setDeepAgentRunning] = useState<boolean>(false);
  const [deepAgentStatus, setDeepAgentStatus] = useState<string | null>(null);
  const [deepAgentError, setDeepAgentError] = useState<string | null>(null);
  const [deepAgentRounds, setDeepAgentRounds] = useState<
    Array<{
      round: number;
      hypotheses: Array<DeepAgentHypothesis & { pocResult: PocResult | null }>;
    }>
  >([]);
  const [showCertificate, setShowCertificate] = useState<boolean>(false);
  const [findingTriage, setFindingTriage] = useState<
    Record<
      string,
      { status: "active" | "acknowledged" | "false_positive" | "remediated"; note?: string }
    >
  >({});
  // Auditor dispositions (migration 0015): the verdict OF RECORD per
  // finding, keyed by DATABASE finding id (`${scanId}:${ord}`) — not by
  // the report's in-memory ids. Loaded per saved scan; written only by a
  // human tap (a button, or accepting the chain's suggestion).
  const [findingDispositions, setFindingDispositions] = useState<
    Record<string, FindingDisposition>
  >({});
  const [dispositionSavingId, setDispositionSavingId] = useState<string | null>(null);
  // One-action adjudication chain state per DB finding id: live progress
  // while the chain runs, then its outcome (verdict + suggestion) until
  // the auditor accepts, redoes, or clears it.
  type FindingAdjudication = {
    running: boolean;
    notice?: string;
    outcome?: AdjudicationOutcome;
    /** Live per-step states while the chain runs (fetch/llm/harness/saved). */
    steps?: Partial<Record<ChainStep, ChainStepState | "running">>;
  };
  const [findingAdjudications, setFindingAdjudications] = useState<
    Record<string, FindingAdjudication>
  >({});

  // Local DB & RAG state
  const [isSavingDb, setIsSavingDb] = useState<boolean>(false);
  const [isSupabaseDbModalOpen, setIsSupabaseDbModalOpen] = useState<boolean>(false);
  const [dbSavedNotice, setDbSavedNotice] = useState<string | null>(null);
  // Which database the app is actually reading (from getDbInfo). Rendered
  // in the header so a wrong-project mismatch is visible at a glance.
  // `state` is the effective connection state: a configured-but-failed
  // database renders as FAILED with its configured identity — never as
  // "not configured" (the old header conflated the two via `error`).
  const [dbInfo, setDbInfo] = useState<{
    host: string | null;
    port: string | null;
    user: string | null;
    database: string | null;
    state: "remote" | "failed" | "unconfigured";
    error: string | null;
  } | null>(null);
  useEffect(() => {
    let cancelled = false;
    void getDbInfo()
      .then((info) => {
        if (!cancelled) setDbInfo(info);
      })
      .catch(() => {
        // getDbInfo returns { error } instead of throwing; a transport
        // failure just leaves the label hidden.
      });
    return () => {
      cancelled = true;
    };
  }, []);
  // Deployed build stamp (#6): short SHA + analyzer version in the header,
  // so a stale cached bundle is visible instead of guessed at.
  const [buildInfo, setBuildInfo] = useState<{
    sha: string;
    shortSha: string;
    builtAt: string;
    analyzerVersion: string | null;
  } | null>(null);
  useEffect(() => {
    let cancelled = false;
    void getBuildInfoFn()
      .then((info) => {
        if (!cancelled) setBuildInfo(info);
      })
      .catch(() => {
        // Stamp is informational; a failed fetch just leaves it hidden.
      });
    return () => {
      cancelled = true;
    };
  }, []);
  const [ragModalFinding, setRagModalFinding] = useState<Finding | null>(null);
  const [ragModalResults, setRagModalResults] = useState<RagChunk[]>([]);
  const [isLoadingRagModal, setIsLoadingRagModal] = useState<boolean>(false);

  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [findingSearch, setFindingSearch] = useState<string>("");
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>(() => {
    const initReport = analyzeInput(defaultSample.body, defaultSample.label);
    const initial: Record<string, boolean> = {};
    initReport.findings.forEach((f, idx) => {
      if (idx < 3 || f.severity === "critical") {
        initial[f.id] = true;
      }
    });
    return initial;
  });
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [disasmFilter, setDisasmFilter] = useState<string>("");

  // Scan history: starts with server initialScans to guarantee SSR hydration parity
  const [scanHistory, setScanHistory] = useState<ScanSummary[]>(initialScans);

  // Sync client-side localStorage AFTER hydration
  useEffect(() => {
    try {
      const saved = localStorage.getItem("kiln_scans_history");
      if (saved) {
        const parsed = JSON.parse(saved) as ScanSummary[];
        if (Array.isArray(parsed) && parsed.length > 0) {
          const map = new Map<string, ScanSummary>();
          initialScans.forEach((s) => map.set(s.id, s));
          parsed.forEach((s) => map.set(s.id, s));
          setScanHistory(
            Array.from(map.values()).sort(
              (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
            ),
          );
        }
      }
    } catch {
      // ignore
    }
  }, [initialScans]);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Run audit analysis on user demand or sample switch
  const handleRunAnalysis = (bodyToAnalyze = contractBody, labelToAnalyze = contractLabel) => {
    if (!bodyToAnalyze.trim()) return;
    // Fresh analysis = fresh scan: drop the previous PoC result / saved id.
    setPocResult(null);
    setPocRunning(false);
    setPocSaved(false);
    setFindingPocRuns({});
    setFindingAdjudications({});
    setSavedScanId(null);
    try {
      const generated = analyzeInput(bodyToAnalyze, labelToAnalyze);
      setReport(generated);

      // Pasted bytecode: resolve unknown selectors + event topics
      // against the 4byte tables (same enrichment as the address fetch,
      // fire-and-forget — the audit stands without it).
      if (looksLikeBytecode(bodyToAnalyze)) {
        resolveFourbyte({
          data: {
            selectors: generated.inventory.selectors
              .filter((s) => !s.signature)
              .map((s) => s.selector),
            topics: (generated.inventory.topics ?? [])
              .filter((t) => !t.signature)
              .map((t) => t.topic),
          },
        })
          .then((fourbyte) => {
            applyFourbyteResults(generated, fourbyte);
            setReport({ ...generated });
          })
          .catch(() => undefined);

        // ResNet1D screening for pasted bytecode — same attach the
        // address paths get inside analyzeAddress, here run directly
        // over the pasted body (fire-and-forget like the fourbyte
        // enrichment: the static audit stands without it).
        attachResnetToReport(generated, bodyToAnalyze, runResnetBrowser)
          .then((attached) => {
            if (attached) setReport({ ...generated });
          })
          .catch(() => undefined);
      }

      // Expand top critical/high findings by default
      const initialExpanded: Record<string, boolean> = {};
      generated.findings.forEach((f, idx) => {
        if (idx < 3 || f.severity === "critical") {
          initialExpanded[f.id] = true;
        }
      });
      setExpandedFindings(initialExpanded);

      // Create a local scan summary
      const crit = generated.findings.filter((f) => f.severity === "critical").length;
      const high = generated.findings.filter((f) => f.severity === "high").length;
      const med = generated.findings.filter((f) => f.severity === "medium").length;
      const low = generated.findings.filter((f) => f.severity === "low").length;
      const info = generated.findings.filter((f) => f.severity === "info").length;

      const newScan: ScanSummary = {
        id: "scan-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 7),
        label: labelToAnalyze,
        inputKind: generated.inputKind,
        contractName: generated.inventory.contractNames[0] ?? null,
        riskScore: generated.riskScore,
        criticalCount: crit,
        highCount: high,
        mediumCount: med,
        lowCount: low,
        infoCount: info,
        createdAt: new Date().toISOString(),
      };

      setScanHistory((prev) => {
        const updated = [
          newScan,
          ...prev.filter((s) => s.label !== labelToAnalyze || s.riskScore !== newScan.riskScore),
        ].slice(0, 30);
        try {
          localStorage.setItem("kiln_scans_history", JSON.stringify(updated));
        } catch {
          // ignore
        }
        return updated;
      });

      // Auto-persist comprehensive record to local DB and RAG knowledgebase
      saveComprehensiveScanFn({
        data: {
          label: labelToAnalyze,
          report: generated,
          body: bodyToAnalyze,
          targetAddress: singleAddress.trim() || null,
          chainId: singleAddressChain,
          compilerVersion: generated.inventory.compiler,
          proxyInfo: proxyInfo ?? null,
          probes: probes ?? [],
          aiReview: aiReview ?? null,
          triageStates: Object.fromEntries(
            Object.entries(findingTriage).map(([k, v]) => [k, v.status]),
          ),
          sourceOrigin: "workbench",
          indexToRag: true,
        },
      })
        .then((saved) => {
          if (saved?.id) setSavedScanId(saved.id);
        })
        .catch((err) => {
          console.warn("[kiln] Auto-persist to DB & RAG notice:", err);
        });
    } catch (err) {
      console.error("[Kiln] Analysis failed:", err);
    }
  };

  // Manual save to Local DB and RAG Knowledgebase
  const handleSaveToLocalDb = async (andIndexRag = true) => {
    if (!report) return;
    setIsSavingDb(true);
    try {
      const certHash =
        "0x" +
        Array.from({ length: 32 }, () =>
          Math.floor(Math.random() * 256)
            .toString(16)
            .padStart(2, "0"),
        ).join("");
      const saved = await saveComprehensiveScanFn({
        data: {
          id: savedScanId ?? undefined,
          label: contractLabel,
          report,
          body: contractBody,
          targetAddress: singleAddress.trim() || null,
          chainId: singleAddressChain,
          compilerVersion: report.inventory.compiler,
          proxyInfo,
          probes,
          aiReview,
          pocResult: pocResult ?? null,
          triageStates: Object.fromEntries(
            Object.entries(findingTriage).map(([k, v]) => [k, v.status]),
          ),
          certHash,
          sourceOrigin: "workbench",
          indexToRag: andIndexRag,
        },
      });
      if (saved?.id) setSavedScanId(saved.id);
      setDbSavedNotice(
        andIndexRag ? "Saved to Supabase DB & Ingested to RAG KB!" : "Saved to Supabase DB!",
      );
      setTimeout(() => setDbSavedNotice(null), 3000);
    } catch (err) {
      console.warn("Supabase DB save failed:", err);
      setDbSavedNotice("Supabase DB save failed: " + String(err));
      setTimeout(() => setDbSavedNotice(null), 3500);
    } finally {
      setIsSavingDb(false);
    }
  };

  // Load a stored scan from Local DB Records
  const handleLoadStoredScan = (scan: StoredScan) => {
    setSelectedSampleId("custom");
    setContractBodyRaw(scan.body);
    setBodyLoadedForAddress(scan.targetAddress ?? null);
    setContractLabel(scan.label);
    setReport(scan.report);
    setFindingAdjudications({});
    setSavedScanId(scan.id);
    setPocResult(scan.pocResult ?? null);
    setPocRunning(false);
    setPocSaved(Boolean(scan.pocResult));
    if (scan.targetAddress) setSingleAddress(scan.targetAddress);
    if (scan.chainId) setSingleAddressChain(scan.chainId);
    if (scan.proxyInfo) setProxyInfo(scan.proxyInfo);
    if (scan.probes) setProbes(scan.probes);
    if (scan.aiReview) setAiReview(scan.aiReview);
    if (scan.triageStates) {
      const formatted: Record<
        string,
        { status: "active" | "acknowledged" | "false_positive" | "remediated" }
      > = {};
      for (const [k, v] of Object.entries(scan.triageStates)) {
        formatted[k] = { status: v as "active" | "acknowledged" | "false_positive" | "remediated" };
      }
      setFindingTriage(formatted);
    }
    setWorkbenchMode("audit");
    setActiveTab("findings");
  };

  const handleLoadStoredScanById = async (scanId: string) => {
    try {
      const full = await getScan({ data: { id: scanId } });
      if (full) handleLoadStoredScan(full);
    } catch (err) {
      console.warn("[kiln] Could not load scan by id:", err);
    }
  };

  // The DATABASE id of a report finding. Findings of a loaded scan carry
  // it directly (`${scanId}:${ord}`); findings of a fresh analysis carry
  // in-memory ids (`r1`, `r2`, …) and map by report position once the
  // scan is saved, because the bulk writer stores findings in report
  // order under `${scanId}:${ord}`. Synthetic findings (Deep Agent
  // hypotheses) have no DB row and return null — no disposition UI, no
  // chain persistence for them.
  const findingDbId = (finding: Finding): string | null => {
    if (finding.id.includes(":")) return finding.id;
    if (finding.id.startsWith("deep-")) return null;
    if (!savedScanId || !report) return null;
    const idx = report.findings.indexOf(finding);
    return idx >= 0 ? `${savedScanId}:${idx}` : null;
  };

  // Load the saved scan's dispositions whenever the saved scan changes.
  useEffect(() => {
    if (!savedScanId) {
      setFindingDispositions({});
      return;
    }
    let cancelled = false;
    getFindingDispositionsFn({ data: { scanId: savedScanId } })
      .then((map) => {
        if (!cancelled) setFindingDispositions(map);
      })
      .catch(() => {
        // Dispositions are additive UI; a failed read leaves none shown
        // rather than breaking the workbench.
      });
    return () => {
      cancelled = true;
    };
  }, [savedScanId]);

  // The human write: a disposition button tap, a note save, or accepting
  // the chain's suggestion. Re-setting the same value is a server-side
  // no-op, so an accidental double-tap costs nothing.
  const handleSetFindingDisposition = async (
    finding: Finding,
    disposition: AuditorDisposition,
    note?: string | null,
  ) => {
    const dbId = findingDbId(finding);
    if (!dbId || dispositionSavingId) return;
    setDispositionSavingId(dbId);
    try {
      const saved = await setFindingDispositionFn({
        data: {
          findingId: dbId,
          disposition,
          note: note !== undefined ? note : (findingDispositions[dbId]?.note ?? null),
        },
      });
      setFindingDispositions((prev) => ({ ...prev, [dbId]: saved }));
    } catch (err) {
      console.warn("[kiln] Disposition save failed:", err);
    } finally {
      setDispositionSavingId(null);
    }
  };

  const handleClearAdjudication = (finding: Finding) => {
    const dbId = findingDbId(finding);
    if (!dbId) return;
    setFindingAdjudications((prev) => {
      const next = { ...prev };
      delete next[dbId];
      return next;
    });
  };

  // One-action adjudication for one finding: fetch/persist state →
  // AI review (reused when the scan already has one) → PoC run (reused
  // when this exact PoC already ran) → saved verdict → suggestion. The
  // chain itself lives in adjudicate-chain.ts; this handler wires it to
  // workbench state and the real server fns / backend client.
  const handleAdjudicateFinding = async (finding: Finding, force = false) => {
    if (!report) return;
    // The finding needs a DB identity: persist the scan first when the
    // analysis has not been saved yet (same payload as the manual save,
    // minus the certificate hash).
    let scanId = savedScanId;
    if (!scanId) {
      try {
        const saved = await saveComprehensiveScanFn({
          data: {
            label: contractLabel,
            report,
            body: contractBody,
            targetAddress: singleAddress.trim() || null,
            chainId: singleAddressChain,
            compilerVersion: report.inventory.compiler,
            proxyInfo,
            probes,
            aiReview,
            triageStates: Object.fromEntries(
              Object.entries(findingTriage).map(([k, v]) => [k, v.status]),
            ),
            sourceOrigin: "workbench",
            indexToRag: false,
          },
        });
        scanId = saved?.id ?? null;
        if (scanId) setSavedScanId(scanId);
      } catch (err) {
        console.warn("[kiln] Adjudication pre-save failed:", err);
      }
    }
    if (!scanId) return;
    const dbId = finding.id.includes(":")
      ? finding.id
      : `${scanId}:${report.findings.indexOf(finding)}`;
    if (!dbId || dbId.endsWith(":-1")) return;
    const dbFinding: Finding = { ...finding, id: dbId };
    const dbFindings: Finding[] = report.findings.map((f, i) => ({
      ...f,
      id: f.id.includes(":") ? f.id : `${scanId}:${i}`,
    }));
    setFindingAdjudications((prev) => ({
      ...prev,
      [dbId]: { running: true, notice: "Starting adjudication…", steps: {} },
    }));
    try {
      const outcome = await runAdjudicationChain(
        {
          scanId,
          finding: dbFinding,
          body: contractBody,
          findings: dbFindings,
          contractName: report.label,
          targetAddress: singleAddress.trim() || null,
          chainId: singleAddressChain,
          aiReview,
          disposition: findingDispositions[dbId] ?? null,
          force,
          // Template 46's POC_TOKEN: the target's most valuable
          // external ERC-20 holding from this report's valuation.
          pocToken: externalTokenCandidate(report, singleAddress.trim() || null),
        },
        {
          requestAiReview: async ({ contractName, body, findings }) =>
            requestAiReview({
              data: {
                contractName,
                body,
                findings,
                fourbyte: fourbyteResultsFromReport(report),
                inventory: report.inventory,
                resnet: report.resnet,
              },
            }),
          persistAiReview: async (review) => {
            setAiReview(review);
            await saveComprehensiveScanFn({
              data: {
                id: scanId!,
                label: report.label,
                report,
                body: contractBody,
                targetAddress: singleAddress.trim() || null,
                chainId: singleAddressChain,
                compilerVersion: report.inventory.compiler,
                proxyInfo,
                probes,
                aiReview: review,
                triageStates: Object.fromEntries(
                  Object.entries(findingTriage).map(([k, v]) => [k, v.status]),
                ),
                sourceOrigin: "workbench",
                indexToRag: false,
              },
            });
          },
          listRuns: async (findingId) => getFindingPocRunsFn({ data: { findingId } }),
          runPoc: async ({ address, chainId, testCode, tokenAddress }) => {
            const poc = await runPocWithRpcRetries(getBackendUrl(), {
              address,
              chainId,
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
            return repaired.fixedCode;
          },
          isCompileError: isPocCompileError,
          saveRun: async (record) => {
            await saveFindingPocResultFn({ data: record });
          },
          onProgress: (notice) =>
            setFindingAdjudications((prev) => ({
              ...prev,
              [dbId]: { ...prev[dbId], running: true, notice },
            })),
          onStep: (stepName, state) =>
            setFindingAdjudications((prev) => ({
              ...prev,
              [dbId]: {
                ...prev[dbId],
                steps: { ...prev[dbId]?.steps, [stepName]: state },
              },
            })),
        },
      );
      setFindingAdjudications((prev) => ({
        ...prev,
        [dbId]: { running: false, outcome },
      }));
      // Mirror a fresh/reused verdict onto the in-memory finding so the
      // card's evidence updates without reloading the scan.
      if (outcome.runStep === "executed" || outcome.runStep === "reused") {
        setReport((prev) =>
          prev
            ? {
                ...prev,
                findings: prev.findings.map((f) =>
                  f.id === finding.id
                    ? {
                        ...f,
                        pocStatus: outcome.verdict,
                        pocOutput: outcome.output ?? f.pocOutput,
                        pocCode: outcome.testCode ?? f.pocCode,
                        pocRunAt: new Date().toISOString(),
                      }
                    : f,
                ),
              }
            : prev,
        );
      }
    } catch (err) {
      setFindingAdjudications((prev) => ({
        ...prev,
        [dbId]: {
          running: false,
          outcome: failedAdjudicationOutcome(
            `Adjudication failed before completing — nothing was written. ${err instanceof Error ? err.message : String(err)}`,
            "fetch",
          ),
        },
      }));
    }
  };

  // Open RAG knowledgebase modal for a specific finding
  const handleOpenRagForFinding = async (finding: Finding) => {
    setRagModalFinding(finding);
    setIsLoadingRagModal(true);
    const q = `${finding.title} ${finding.detector} ${finding.swc ?? ""}`.trim();
    try {
      const res = await queryRagKnowledgebaseFn({
        data: { query: q, limit: 8 },
      });
      setRagModalResults(res);
    } catch {
      setRagModalResults([]);
    } finally {
      setIsLoadingRagModal(false);
    }
  };

  // Handle sample selection
  const handleSelectSample = (sample: Sample) => {
    setSelectedSampleId(sample.id);
    setContractBodyRaw(sample.body);
    setBodyLoadedForAddress(null);
    setContractLabel(sample.label);
    handleRunAnalysis(sample.body, sample.label);
  };

  // Handle single address fetch from public RPC & Sourcify
  const handleFetchSingleAddress = async () => {
    const clean = singleAddress.trim();
    if (!isValidEvmAddress(clean)) {
      setAddressFetchError("Invalid EVM address format (expected 0x + 40 hex characters)");
      return;
    }
    setIsFetchingAddress(true);
    setAddressFetchError(null);
    try {
      const res = await analyzeAddress(clean, singleAddressChain, undefined, {
        resnetRunner: runResnetBrowser,
      });
      // Resolve unknown selectors + event topics against the 4byte
      // tables (server-side DB lookup). Best-effort: the audit stands
      // without it, and the enriched report is what AI / Deep Agent /
      // save all see downstream.
      try {
        const fourbyte = await resolveFourbyte({
          data: {
            selectors: res.report.inventory.selectors
              .filter((s) => !s.signature)
              .map((s) => s.selector),
            topics: (res.report.inventory.topics ?? [])
              .filter((t) => !t.signature)
              .map((t) => t.topic),
          },
        });
        applyFourbyteResults(res.report, fourbyte);
      } catch {
        // Enrichment failed — keep the un-enriched report.
      }
      setSelectedSampleId("custom");
      setContractBodyRaw(res.rawBody);
      setBodyLoadedForAddress(clean);
      setContractLabel(res.report.label);
      setReport(res.report);
      setActiveTab("findings");

      // Auto-inspect for proxy architecture
      detectProxyArchitecture(clean, singleAddressChain)
        .then((proxy) => setProxyInfo(proxy))
        .catch(() => setProxyInfo(null));

      // Auto-run view probes
      probeContractInterfaces(clean, singleAddressChain)
        .then((pr) => setProbes(pr))
        .catch(() => setProbes([]));
    } catch (err) {
      setAddressFetchError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsFetchingAddress(false);
    }
  };

  // Inspect item from batch pipeline in workbench
  const handleInspectPipelineItem = (pipelineReport: Report, rawBody: string, label: string) => {
    // If label or id looks like an address, try proxy detection
    const match = label.match(/0x[0-9a-fA-F]{40}/);
    setSelectedSampleId("custom");
    setContractBodyRaw(rawBody);
    setBodyLoadedForAddress(match?.[0] ?? null);
    setContractLabel(label);
    setReport(pipelineReport);
    setWorkbenchMode("audit");
    setActiveTab("findings");
    if (match && match[0]) {
      setSingleAddress(match[0]);
      detectProxyArchitecture(match[0], singleAddressChain)
        .then((proxy) => setProxyInfo(proxy))
        .catch(() => setProxyInfo(null));
      probeContractInterfaces(match[0], singleAddressChain)
        .then((pr) => setProbes(pr))
        .catch(() => setProbes([]));
    }
  };

  // ---- Interactive Audit & PoC: source box --------------------------------
  const handleInteractiveSourceChange = (code: string) => {
    setInteractiveSource((s) => applyInteractiveEdit(s, code));
  };

  // Load the shared selected address's source into the interactive box.
  // This is the audit tab's own fetch path — analyzeAddress with the
  // browser ResNet runner, same arguments as handleFetchSingleAddress —
  // but the result fills ONLY the interactive box: the workbench's body,
  // report and saved-record flow are untouched, so experimenting in the
  // sandbox can never corrupt the audit in progress.
  const handleLoadInteractiveSource = async () => {
    const clean = singleAddress.trim();
    if (!isValidEvmAddress(clean)) {
      setInteractiveSource((s) =>
        applyInteractiveLoadError(
          s,
          "Invalid EVM address format (expected 0x + 40 hex characters)",
        ),
      );
      return;
    }
    setInteractiveSource((s) => beginInteractiveLoad(s));
    try {
      const res = await analyzeAddress(clean, singleAddressChain, undefined, {
        resnetRunner: runResnetBrowser,
      });
      setInteractiveSource((s) => settleInteractiveLoad(s, clean, res));
    } catch (err) {
      setInteractiveSource((s) =>
        applyInteractiveLoadError(s, err instanceof Error ? err.message : String(err)),
      );
    }
  };

  // The PoC repair callback every workbench SmartPoC run hands to
  // runSmartPoc: the chain's repair machinery (requestPocRepair →
  // repairPocCode), nothing new. runSmartPoc invokes it ONLY when a
  // run ends in a solc compile error — one bounded attempt, the
  // re-run carries no repair callback, and assertion/verdict outcomes
  // are never re-rolled. A repair that itself fails keeps the original
  // compile-error result, with the failure noted in its logs.
  const smartPocRepair = async (source: string, logs: string): Promise<string> => {
    const repaired = await requestPocRepair({
      data: {
        contractName: report?.label ?? "TargetContract",
        originalCode: source,
        errorLogs: logs,
        body: contractBody,
      },
    });
    return repaired.fixedCode;
  };

  // Single-PoC run with one LLM repair on compile failure (inside
  // runSmartPoc, via the repair callback). Returns the final PoC
  // result + the code that actually executed (the repaired code when
  // repair ran).
  const runSinglePocWithRepair = async (address: string, testCode: string) => {
    const poc = await runPocWithRpcRetries(getBackendUrl(), {
      address,
      testCode,
      repair: smartPocRepair,
    });
    return { poc, testCode: poc.executedSource ?? testCode };
  };

  // --- Per-finding PoC runs (Run button on each finding's Attack Contract
  // block). The displayed snippet is wrapped by wrapPocSnippetWithReason
  // into a runnable Foundry Test before it is passed to runPocOnBackend;
  // when wrapping fails (null), the diagnostic reason is shown up front
  // in the output, and zero tests ran maps to "error", NEVER "passed"
  // (the old false-PASS lesson — forge exits 0 on no match).
  const POC_OUTPUT_CAP = 4000;
  const NO_TESTS_RE = /no tests (match|found)|ran 0 tests|0 passed;\s*0 failed/i;
  const newRunId = () => {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function")
      return crypto.randomUUID();
    const bytes = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  };
  const mapFindingPocStatus = (poc: PocResult): PocRunResult["status"] => {
    // A run that aborted on a template's TODO precondition is an
    // unadapted scaffold — not a verdict, not an infra error.
    if (hasUnadaptedEvidence(poc.logs)) return "unadapted";
    if (poc.status === "passed" && NO_TESTS_RE.test(poc.logs ?? "")) return "error";
    if (poc.status === "passed") return "passed";
    if (poc.status === "failed") return "failed";
    return "error"; // "error" | "skipped" | "backend_unreachable" are all infra, not a verdict
  };
  const attemptFindingPocSave = async (result: PocRunResult, findingId: string) => {
    setFindingPocRuns((prev) => ({
      ...prev,
      [findingId]: { ...prev[findingId]!, running: false, save: "saving", saveError: null },
    }));
    try {
      const cfg = getStoredSupabaseConfig();
      if (!cfg.enabled) {
        setFindingPocRuns((prev) => ({
          ...prev,
          [findingId]: {
            ...prev[findingId]!,
            save: "not-configured",
            saveError: "Supabase not configured — result not saved.",
          },
        }));
        return;
      }
      await savePocRun(result, cfg);
      setFindingPocRuns((prev) => ({
        ...prev,
        [findingId]: { ...prev[findingId]!, save: "saved", saveError: null },
      }));
    } catch (err) {
      setFindingPocRuns((prev) => ({
        ...prev,
        [findingId]: {
          ...prev[findingId]!,
          save: "failed",
          saveError: err instanceof Error ? err.message : String(err),
        },
      }));
    }
  };
  const handleRunFindingPoc = async (finding: Finding) => {
    let source = finding.exploitSolidity ?? "";
    let wrapOutcome = wrapPocSnippetWithReason(source);
    let wrapped = wrapOutcome.wrapped;
    if (!wrapped) {
      const isTest = /\bcontract\s+\w+\s+is\s+[^{]*\bTest\b/.test(source);
      const hasTestFn = /function\s+test_\w*\s*\(|function\s+testPoc\s*\(/.test(source);
      if (!isTest || !hasTestFn) {
        const fallbacks = selectPocFallbacks([finding], 1);
        if (fallbacks.length > 0 && fallbacks[0]?.source) {
          source = fallbacks[0].source;
          wrapOutcome = wrapPocSnippetWithReason(source);
          wrapped = wrapOutcome.wrapped;
        }
      }
    }
    // Why wrapping failed (null when it succeeded) — shown up front in
    // the output below instead of a silent null.
    const wrapReason = wrapOutcome.reason;
    const wrapDiag =
      !wrapped && wrapReason
        ? `Wrapper could not wrap this snippet: ${wrapReason}. Sent the raw snippet instead.`
        : null;
    const testCode = wrapped ? wrapped.testFile : source;
    if (!source.trim() || findingPocRunLockRef.current) return;
    findingPocRunLockRef.current = true;
    const startedAt = new Date().toISOString();
    const runId = newRunId();
    setFindingPocRuns((prev) => ({
      ...prev,
      [finding.id]: { running: true, result: null, save: "idle", saveError: null },
    }));
    try {
      const isTestFinal = /\bcontract\s+\w+\s+is\s+[^{]*\bTest\b/.test(testCode);
      const hasTestFnFinal = /function\s+test_\w*\s*\(|function\s+testPoc\s*\(/.test(testCode);
      if (!wrapped && (!isTestFinal || !hasTestFnFinal)) {
        setFindingPocRuns((prev) => ({
          ...prev,
          [finding.id]: {
            running: false,
            result: {
              id: runId,
              source,
              status: "skipped",
              startedAt,
              finishedAt: new Date().toISOString(),
              durationMs: 0,
              chainId: SUPPORTED_CHAINS.find((c) => c.id === singleAddressChain)?.chainId ?? 1,
              exitCode: null,
              output:
                `${wrapDiag ? `${wrapDiag}\n` : ""}This finding's PoC is a conceptual guideline or pseudocode, not an automated Solidity attack contract or test harness. Use the 'Interactive Audit & PoC' tab or 'AI Security Review' to construct and run an exploit against this target.`,
              truncated: false,
            },
            save: "idle",
            saveError: null,
          },
        }));
        return;
      }
      const addr = singleAddress.trim();
      if (!addr || !isValidEvmAddress(addr)) {
        // No valid target — record an error row without calling the backend
        // (runPocOnBackend would return "skipped"). Not a real run, so no
        // save is attempted; save stays "idle" and no save line renders.
        setFindingPocRuns((prev) => ({
          ...prev,
          [finding.id]: {
            running: false,
            result: {
              id: runId,
              source,
              status: "error",
              startedAt,
              finishedAt: new Date().toISOString(),
              durationMs: 0,
              chainId: SUPPORTED_CHAINS.find((c) => c.id === singleAddressChain)?.chainId ?? 1,
              exitCode: null,
              output: "No valid 0x target address — fetch an on-chain address first.",
              truncated: false,
            },
            save: "idle",
            saveError: null,
          },
        }));
        return;
      }
      // Unadapted-template pre-check (shared with the adjudication
      // chain and the PoC Audits page): the test about to run IS a
      // fallback template whose required TODO constants are still
      // zero — it would abort on its own precondition and file as a
      // verdict it never earned. Save it as "unadapted" WITHOUT
      // calling the backend.
      const todoCheck = unadaptedTemplateCheck(testCode);
      if (todoCheck) {
        const result: PocRunResult = {
          id: runId,
          source: testCode,
          status: "unadapted",
          startedAt,
          finishedAt: new Date().toISOString(),
          durationMs: 0,
          chainId: SUPPORTED_CHAINS.find((c) => c.id === singleAddressChain)?.chainId ?? 1,
          exitCode: null,
          output: `Finding input SHA3-256: ${pocInputDigest(source)}\n${unadaptedTemplateOutput(todoCheck.file, todoCheck.unfilled)}`,
          truncated: false,
        };
        setFindingPocRuns((prev) => ({
          ...prev,
          [finding.id]: { running: false, result, save: "idle", saveError: null },
        }));
        await attemptFindingPocSave(result, finding.id);
        return;
      }
      // POC_TOKEN for token-rescue harnesses (template 46 reads it):
      // the target's external-token candidate from this report's
      // valuation, only when the harness references it.
      const tokenAddress = testCode.includes("POC_TOKEN")
        ? (externalTokenCandidate(report, addr) ?? undefined)
        : undefined;
      const poc = await runPocWithRpcRetries(getBackendUrl(), {
        address: addr,
        testCode,
        chainId: singleAddressChain,
        ...(tokenAddress ? { tokenAddress } : {}),
        // Same bounded compile repair the adjudicate chain gets: a
        // generated PoC that dies on a solc type error (the
        // bytes32→uint256 vm.load slip) is repaired once from the
        // compiler output instead of ending as a terminal error.
        repair: smartPocRepair,
      });
      // Release the run lock as soon as the backend call returns — the
      // save attempt below must not block other runs (it can take up to
      // the 30s save timeout on a failing endpoint). The finally still
      // releases on every other path.
      findingPocRunLockRef.current = false;
      const finishedAt = new Date().toISOString();
      const status = mapFindingPocStatus(poc);
      // Zero-tests-matched must never read as passed: when the backend
      // claimed "passed" but no test ran, the logs say so explicitly.
      // The note depends on whether the snippet was wrapped: a wrapped
      // run DID produce a runnable test, so "attack contract, not a
      // runnable test" would be wrong — it means no test matched the
      // backend's filter instead.
      const zeroTestsNote = wrapped
        ? "Wrapped test did not run — no tests matched the backend's filter."
        : "No test functions ran — this PoC snippet is an attack contract, not a runnable Foundry test.";
      const fullLogs =
        status === "error" && poc.status === "passed"
          ? `${poc.logs ?? ""}\n${zeroTestsNote}`
          : (poc.logs ?? "");
      // When the wrapper filled default args, say so up front — the
      // guessed args may be wrong, and a FAIL with defaults is
      // informative. When wrapping failed, say WHY up front instead
      // of a silent null. Truncation is computed on the combined text.
      const wrapLine = wrapDiag ?? wrapped?.note ?? null;
      const displayLogs = `Finding input SHA3-256: ${pocInputDigest(source)}\n${wrapLine ? `${wrapLine}\n` : ""}${fullLogs}`;
      const truncated = displayLogs.length > POC_OUTPUT_CAP;
      const result: PocRunResult = {
        id: runId,
        // The code that actually executed — the repaired PoC when the
        // compile repair ran, not the broken draft it replaced.
        source: poc.executedSource ?? testCode,
        status,
        startedAt,
        finishedAt,
        durationMs: poc.durationMs ?? 0,
        chainId: SUPPORTED_CHAINS.find((c) => c.id === singleAddressChain)?.chainId ?? 1,
        exitCode: null, // the backend response carries no exit code
        output: truncated ? displayLogs.slice(0, POC_OUTPUT_CAP) : displayLogs,
        truncated,
      };
      setFindingPocRuns((prev) => ({
        ...prev,
        [finding.id]: { running: false, result, save: "idle", saveError: null },
      }));
      await attemptFindingPocSave(result, finding.id);
    } finally {
      findingPocRunLockRef.current = false;
    }
  };
  // Retry Save calls persistence ONLY — it re-saves the stored result and
  // never reruns the PoC.
  const handleRetryFindingPocSave = async (findingId: string) => {
    const run = findingPocRuns[findingId];
    if (!run?.result || run.save !== "failed") return;
    await attemptFindingPocSave(run.result, findingId);
  };

  // Request AI Threat Modeling & Foundry Test Suite (OpenRouter API)
  const handleTriggerAiReview = async () => {
    if (!report) return;
    setIsLoadingAi(true);
    try {
      const res = await requestAiReview({
        data: {
          contractName: report.label,
          body: contractBody,
          findings: report.findings,
          fourbyte: fourbyteResultsFromReport(report),
          inventory: report.inventory,
          resnet: report.resnet,
        },
      });
      setAiReview(res);
      setActiveTab("ai");

      // Auto-run the generated PoC on the local Termux backend (forge fork),
      // with one LLM repair if it fails to compile — then persist the
      // outcome to Supabase with this scan.
      const addr = singleAddress.trim();
      if (!addr || !isValidEvmAddress(addr) || !res.foundryTestCode?.trim()) {
        setPocResult({
          status: "skipped",
          logs: "Auto PoC skipped — fetch an on-chain address first, then re-generate the review.",
          durationMs: 0,
          runAt: new Date().toISOString(),
        });
        // No run — download the original PoC as before.
        if (res.foundryTestCode?.trim()) {
          downloadFile("Exploit.t.sol", res.foundryTestCode);
        }
        return;
      }
      setPocRunning(true);
      setPocSaved(false);
      const { poc, testCode } = await runSinglePocWithRepair(addr, res.foundryTestCode);
      setPocResult(poc);
      setPocRunning(false);
      // The downloaded file + saved review carry the FINAL PoC (repaired
      // when repair ran) — the user downloads the working test, not the
      // broken original, and the record keeps what actually ran.
      const finalReview = { ...res, foundryTestCode: testCode };
      setAiReview(finalReview);
      downloadFile("Exploit.t.sol", testCode);
      // Upsert the same scan row (when known) with the AI review + PoC result.
      // indexToRag: false — the analysis auto-persist already indexed this report.
      saveComprehensiveScanFn({
        data: {
          id: savedScanId ?? undefined,
          label: report.label,
          report,
          body: contractBody,
          targetAddress: addr,
          chainId: singleAddressChain,
          compilerVersion: report.inventory.compiler,
          proxyInfo: proxyInfo ?? null,
          probes: probes ?? [],
          aiReview: finalReview,
          pocResult: poc,
          triageStates: Object.fromEntries(
            Object.entries(findingTriage).map(([k, v]) => [k, v.status]),
          ),
          sourceOrigin: "workbench",
          indexToRag: false,
        },
      })
        .then((saved) => {
          if (saved?.id) setSavedScanId(saved.id);
          setPocSaved(true);
        })
        .catch((err) => {
          console.warn("[kiln] PoC result save notice:", err);
        });
    } catch (err) {
      console.warn("[Kiln] AI review failed:", err);
    } finally {
      setIsLoadingAi(false);
    }
  };

  // Deep Agent — DeepRL-style agentic exploit search. The browser
  // orchestrates because PoC execution lives on the phone backend:
  //   propose (LLM round) -> run each PoC on the fork -> feed the
  //   pass/fail back as the reward signal -> next round goes deeper
  //   on confirmed surfaces, never repeats a refuted hypothesis.
  // Bounded: at most 3 rounds, 2 hypotheses per round (server caps).
  const DEEP_AGENT_MAX_ROUNDS = 3;
  const handleRunDeepAgent = async () => {
    if (!report) return;
    const addr = singleAddress.trim();
    if (!addr || !isValidEvmAddress(addr)) {
      setDeepAgentError(
        "Fetch an on-chain address first — the Deep Agent proves hypotheses with fork PoCs.",
      );
      return;
    }
    setDeepAgentRunning(true);
    setDeepAgentError(null);
    setDeepAgentRounds([]);
    setDeepAgentStatus("Round 1: proposing hypotheses…");
    const priorResults: DeepAgentPriorResult[] = [];
    const rounds: Array<{
      round: number;
      hypotheses: Array<DeepAgentHypothesis & { pocResult: PocResult | null }>;
    }> = [];
    try {
      for (let round = 1; round <= DEEP_AGENT_MAX_ROUNDS; round += 1) {
        // Confirmed hypotheses join the findings so the next round goes
        // deeper on the proven attack surface.
        const confirmedFindings: Finding[] = rounds.flatMap((r) =>
          r.hypotheses
            .filter((h) => classifyPocEvidence({ code: h.foundryTestCode, result: h.pocResult, target: addr, chainId: singleAddressChain }).stage === "reproduced")
            .map((h, i) => ({
              id: `deep-${r.round}-${i}`,
              severity: h.severity,
              swc: null,
              title: h.title,
              confidence: "high" as const,
              detector: h.detector,
              summary: `Deep Agent test assertions reproduced on fork: ${h.hypothesis}`,
              walkthrough: "",
              exploitSolidity: h.foundryTestCode,
              remediationSolidity: "",
              locationFn: null,
              locationLine: null,
              snippet: "",
            })),
        );
        const res = await requestDeepAgentRound({
          data: {
            contractName: report.label,
            body: contractBody,
            findings: [...report.findings, ...confirmedFindings],
            priorResults,
            round,
            fourbyte: fourbyteResultsFromReport(report),
          },
        });
        if (res.hypotheses.length === 0) {
          setDeepAgentStatus(
            res.stopReason
              ? `Search stopped: ${res.stopReason}`
              : "Search stopped: no new hypotheses.",
          );
          break;
        }
        const roundRun: {
          round: number;
          hypotheses: Array<DeepAgentHypothesis & { pocResult: PocResult | null }>;
        } = {
          round,
          hypotheses: [],
        };
        rounds.push(roundRun);
        setDeepAgentRounds([...rounds]);
        let stoppedOnError = false;
        for (const h of res.hypotheses) {
          setDeepAgentStatus(`Round ${round}: running PoC for "${h.title}"…`);
          let testCode = h.foundryTestCode;
          let poc = await runPocWithRpcRetries(getBackendUrl(), { address: addr, testCode, chainId: singleAddressChain });
          // Repair loop (same as the worker): a PoC that fails to
          // COMPILE gets ONE LLM repair + one re-run.
          if (poc.status === "error" && isPocCompileError(poc.logs ?? "")) {
            setDeepAgentStatus(
              `Round ${round}: PoC for "${h.title}" failed to compile — asking the model to repair it…`,
            );
            try {
              const repaired = await requestPocRepair({
                data: {
                  contractName: report.label,
                  originalCode: testCode,
                  errorLogs: poc.logs ?? "",
                  body: contractBody,
                },
              });
              testCode = repaired.fixedCode;
              poc = await runPocWithRpcRetries(getBackendUrl(), { address: addr, testCode, chainId: singleAddressChain });
            } catch (repairErr) {
              setDeepAgentError(
                `PoC repair failed: ${repairErr instanceof Error ? repairErr.message : String(repairErr)} — stopping the search.`,
              );
              stoppedOnError = true;
              break;
            }
          }
          const outcome =
            poc.status === "passed" ? "confirmed" : poc.status === "failed" ? "refuted" : "error";
          roundRun.hypotheses.push({ ...h, foundryTestCode: testCode, pocResult: poc });
          priorResults.push({
            title: h.title,
            detector: h.detector,
            outcome,
            pocLogs: (poc.logs ?? "").slice(0, 1500),
          });
          setDeepAgentRounds([...rounds]);
          if (outcome === "error") {
            setDeepAgentError(
              `PoC run failed (${poc.status}): ${(poc.error ?? poc.logs ?? "").slice(0, 300)} — stopping the search.`,
            );
            stoppedOnError = true;
            break;
          }
        }
        if (stoppedOnError) break;
        if (round === DEEP_AGENT_MAX_ROUNDS) {
          setDeepAgentStatus("Search complete: max rounds reached.");
        } else {
          setDeepAgentStatus(`Round ${round} done — proposing round ${round + 1}…`);
        }
      }
    } catch (err) {
      setDeepAgentError(`Deep Agent failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setDeepAgentRunning(false);
    }
  };

  // Run on-chain read & interface probes
  const handleRunManualProbe = async () => {
    const targetAddr = singleAddress.trim();
    if (!targetAddr || !isValidEvmAddress(targetAddr)) {
      setAddressFetchError("Please enter a valid EVM address in the fetch bar first.");
      return;
    }
    setIsProbing(true);
    try {
      const pr = await probeContractInterfaces(targetAddr, singleAddressChain);
      setProbes(pr);
      setActiveTab("probe");
    } catch (err) {
      console.warn("[Kiln] State probe failed:", err);
    } finally {
      setIsProbing(false);
    }
  };

  // Detect input type
  const isBytecode = useMemo(() => looksLikeBytecode(contractBody.trim()), [contractBody]);

  // Copy helper
  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Filtered findings
  const filteredFindings = useMemo(() => {
    if (!report) return [];
    return filterFindings(report.findings, severityFilter, findingSearch);
  }, [report, severityFilter, findingSearch]);

  // Handle file upload
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        const cleanName = file.name.replace(/\.[^/.]+$/, "");
        setSelectedSampleId("custom");
        setContractBodyRaw(content);
        setBodyLoadedForAddress(null);
        setContractLabel(cleanName);
        handleRunAnalysis(content, cleanName);
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  // Delete scan from history
  const handleDeleteScan = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setScanHistory((prev) => {
      const next = prev.filter((s) => s.id !== id);
      try {
        localStorage.setItem("kiln_scans_history", JSON.stringify(next));
      } catch {
        // ignore
      }
      return next;
    });
  };

  // Format full markdown report
  const generateMarkdownReport = (): string => {
    if (!report) return "";
    const contractAddress = bodyLoadedForAddress || singleAddress || null;
    const lines: string[] = [
      `# Kiln Security Audit Report: ${report.label}`,
      "",
      `| Metric | Value |`,
      `| :--- | :--- |`,
      `| **Audit Timestamp** | ${new Date().toUTCString()} |`,
      `| **Target Contract** | ${report.label} |`,
      ...(contractAddress ? [`| **Target Address** | \`${contractAddress}\` |`] : []),
      `| **Target Chain** | ${singleAddressChain || "ethereum"} |`,
      `| **Input Type** | ${report.inputKind.toUpperCase()} |`,
      `| **Overall Risk Score** | **${report.riskScore}/100** (${risk.label}) |`,
      "",
      `## 1. Executive Summary`,
      "",
      report.summary,
      "",
    ];

    if (aiReview) {
      lines.push("### AI Executive Review");
      lines.push(`- **Overall Verdict**: **${aiReview.overallVerdict.toUpperCase()}**`);
      if (aiReview.summary) {
        lines.push("");
        lines.push(aiReview.summary);
      }
      lines.push("");
    }

    lines.push("## 2. Vulnerability Overview");
    lines.push("");
    lines.push(`| Severity | Findings Count |`);
    lines.push(`| :--- | :--- |`);
    lines.push(`| 🔴 Critical | ${report.findings.filter((f) => f.severity === "critical").length} |`);
    lines.push(`| 🟠 High | ${report.findings.filter((f) => f.severity === "high").length} |`);
    lines.push(`| 🟡 Medium | ${report.findings.filter((f) => f.severity === "medium").length} |`);
    lines.push(`| 🔵 Low | ${report.findings.filter((f) => f.severity === "low").length} |`);
    lines.push(`| ⚪ Informational | ${report.findings.filter((f) => f.severity === "info").length} |`);
    lines.push("");

    lines.push("## 3. Findings Breakdown & Proofs of Concept");
    lines.push("");

    report.findings.forEach((f, idx) => {
      const severityEmoji =
        f.severity === "critical"
          ? "🔴"
          : f.severity === "high"
            ? "🟠"
            : f.severity === "medium"
              ? "🟡"
              : f.severity === "low"
                ? "🔵"
                : "⚪";
      lines.push(`### ${idx + 1}. [${f.severity.toUpperCase()}] ${f.title}`);
      lines.push("");
      lines.push(`- **Severity**: ${severityEmoji} ${f.severity.toUpperCase()}`);
      lines.push(`- **Detector**: \`${f.detector}\``);
      if (f.swc) lines.push(`- **SWC Classification**: [SWC-${f.swc}](https://swcregistry.io/docs/SWC-${f.swc})`);
      lines.push(`- **Confidence**: ${f.confidence}`);
      if (f.locationFn) {
        lines.push(
          `- **Location**: \`${f.locationFn}\`${f.locationLine ? ` (Line ${f.locationLine})` : ""}`,
        );
      }
      if (f.corroborated) {
        lines.push(`- **Corroboration**: ${typeof f.corroborated === "string" ? f.corroborated : "Confirmed"}`);
      }
      const disposition = findingDispositions[f.id];
      if (disposition) {
        lines.push(`- **Triage Disposition**: \`${disposition.state.toUpperCase()}\`${disposition.note ? ` — ${disposition.note}` : ""}`);
      }
      lines.push("");
      lines.push(`#### Description`);
      lines.push(f.summary);
      lines.push("");
      lines.push(`#### Technical Walkthrough`);
      lines.push(f.walkthrough);
      lines.push("");
      if (f.snippet) {
        lines.push(`#### Vulnerable Code Snippet`);
        lines.push("```solidity");
        lines.push(f.snippet);
        lines.push("```");
        lines.push("");
      }
      const pocCode = f.exploitSolidity || f.pocCode;
      if (pocCode) {
        lines.push(`#### Proof of Concept (Exploit Scenario)`);
        lines.push("```solidity");
        lines.push(pocCode);
        lines.push("```");
        lines.push("");
      }
      if (f.pocStatus || f.pocOutput) {
        lines.push(`#### SmartPoC Execution Evidence`);
        lines.push(`- **Status**: \`${(f.pocStatus || "unknown").toUpperCase()}\``);
        if (f.pocRunAt) lines.push(`- **Executed At**: ${f.pocRunAt}`);
        if (f.pocDurationMs) lines.push(`- **Duration**: ${f.pocDurationMs}ms`);
        if (f.pocOutput) {
          lines.push("");
          lines.push("```text");
          lines.push(f.pocOutput);
          lines.push("```");
        }
        lines.push("");
      }
      if (f.remediationSolidity) {
        lines.push(`#### Recommended Remediation`);
        lines.push("```solidity");
        lines.push(f.remediationSolidity);
        lines.push("```");
        lines.push("");
      }
      lines.push("---");
      lines.push("");
    });

    if (aiReview?.foundryTestCode) {
      lines.push("## 4. Foundry Fork Test Suite");
      lines.push("");
      lines.push("```solidity");
      lines.push(aiReview.foundryTestCode);
      lines.push("```");
      lines.push("");
    }

    if (probes.length > 0) {
      lines.push("## 5. Active Call Probes");
      lines.push("");
      probes.forEach((p) => {
        lines.push(`- **Selector**: \`${p.selector}\` | **Signature**: \`${p.signature || "unknown"}\` | **State**: \`${p.resultState}\``);
        if (p.returnValue) lines.push(`  - Return Value: \`${p.returnValue}\``);
        if (p.revertReason) lines.push(`  - Revert Reason: \`${p.revertReason}\``);
      });
      lines.push("");
    }

    lines.push("---");
    lines.push("*Security Audit Report generated by Kiln. Automated scan results and AI analyses should be verified with comprehensive dynamic testing and formal verification.*");
    return lines.join("\n");
  };

  const handleDownloadMarkdownReport = () => {
    const content = generateMarkdownReport();
    if (!content) return;
    const safeName = (report?.label || "audit-report")
      .replace(/[^a-zA-Z0-9_-]/g, "_")
      .toLowerCase();
    downloadFile(`${safeName}-security-report.md`, content);
  };

  // Risk Score color helper

  const risk = report
    ? getRiskColor(report.riskScore)
    : { text: "text-stone-400", bg: "bg-stone-500", ring: "ring-stone-500/30", label: "PENDING" };

  // Parse disassembly lines for bytecode viewer
  const disasmLines = useMemo(() => {
    if (!report?.inventory.disassembly) return [];
    return report.inventory.disassembly
      .split("\n")
      .filter((l) => Boolean(l.trim()))
      .filter((l) => !disasmFilter || l.toLowerCase().includes(disasmFilter.toLowerCase().trim()));
  }, [report, disasmFilter]);

  // Full disassembly for the CFG: the stored inventory.disassembly is capped
  // at 420 instructions, which truncates the CFG for most contracts. When
  // the raw input is bytecode, recompute the full stream here (in memory,
  // never persisted) and feed the CFG that; otherwise fall back to the
  // stored text and the viewer shows its truncation badge.
  const cfgDisassembly = useMemo(() => {
    if (looksLikeBytecode(contractBody.trim())) {
      const full = fullDisassembly(contractBody);
      if (full) return full;
    }
    return report?.inventory.disassembly ?? "";
  }, [contractBody, report]);

  // Entering the Interactive tab: offer the source the workbench holds
  // for its selected address. The pairing check (bodyLoadedForAddress)
  // is what makes the held body trustworthy; applyWorkbenchPrefill then
  // fills only a pristine box, so a mode switch can never silently
  // replace sandbox work (see lib/audit/interactive-source.ts).
  useEffect(() => {
    if (workbenchMode !== "interactive") return;
    const address = singleAddress.trim();
    const held =
      bodyLoadedForAddress !== null &&
      address !== "" &&
      bodyLoadedForAddress.toLowerCase() === address.toLowerCase();
    setInteractiveSource((s) =>
      applyWorkbenchPrefill(s, {
        address,
        heldBody: held ? contractBody : null,
        heldBodyIsBytecode: held ? isBytecode : false,
      }),
    );
    // Fires on entering interactive mode; the workbench values are read
    // from the render that flipped the mode.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workbenchMode]);

  return {
    fileInputRef,
    handleFileUpload,
    setWorkbenchMode,
    workbenchMode,
    setIsSupabaseDbModalOpen,
    dbInfo,
    buildInfo,
    handleSaveToLocalDb,
    isSavingDb,
    setShowCertificate,
    handleRunAnalysis,
    dbSavedNotice,
    setDbSavedNotice,
    handleInspectPipelineItem,
    handleLoadStoredScan,
    setContractBody,
    setContractLabel,
    handleLoadStoredScanById,
    singleAddress,
    setSingleAddress,
    setAddressFetchError,
    singleAddressChain,
    setSingleAddressChain,
    handleFetchSingleAddress,
    isFetchingAddress,
    addressFetchError,
    interactiveSource,
    handleInteractiveSourceChange,
    handleLoadInteractiveSource,
    proxyInfo,
    handleSelectSample,
    selectedSampleId,
    setSelectedSampleId,
    contractLabel,
    isBytecode,
    contractBody,
    setReport,
    copyToClipboard,
    copiedKey,
    report,
    risk,
    probes,
    setActiveTab,
    activeTab,
    aiReview,
    handleTriggerAiReview,
    handleRunManualProbe,
    scanHistory,
    generateMarkdownReport,
    handleDownloadMarkdownReport,
    setSeverityFilter,
    severityFilter,
    findingSearch,
    setFindingSearch,
    filteredFindings,
    expandedFindings,
    findingPocRuns,
    setExpandedFindings,
    handleRunFindingPoc,
    findingPocRunning,
    handleRetryFindingPocSave,
    findingTriage,
    setFindingTriage,
    findingDispositions,
    findingDbId,
    handleSetFindingDisposition,
    dispositionSavingId,
    findingAdjudications,
    handleAdjudicateFinding,
    handleClearAdjudication,
    handleOpenRagForFinding,
    disasmLines,
    setBytecodeSubView,
    bytecodeSubView,
    disasmFilter,
    setDisasmFilter,
    cfgDisassembly,
    isLoadingAi,
    pocRunning,
    pocResult,
    pocSaved,
    handleRunDeepAgent,
    deepAgentRunning,
    deepAgentStatus,
    deepAgentError,
    deepAgentRounds,
    isProbing,
    getRiskColor,
    handleDeleteScan,
    showCertificate,
    ragModalFinding,
    setRagModalFinding,
    isLoadingRagModal,
    ragModalResults,
    isSupabaseDbModalOpen,
  };
}
export type WorkbenchController = ReturnType<typeof useWorkbenchController>;
