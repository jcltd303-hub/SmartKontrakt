import { classifyPocEvidence } from "@/lib/audit/poc-evidence";
import { downloadFile } from "@/lib/download-file";
import { SUPPORTED_CHAINS, analyzeAddress, isValidEvmAddress } from "@/lib/audit/address-fetcher";
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
import type { ScanSummary, StoredScan } from "@/lib/audit/persist.server";
import { selectPocFallbacks } from "@/lib/audit/poc-fallbacks";
import { wrapPocSnippetWithReason } from "@/lib/audit/poc-wrap";
import { detectProxyArchitecture, type ProxyAnalysis } from "@/lib/audit/proxy-resolver";
import type { RagChunk } from "@/lib/audit/rag.server";
import { type Sample } from "@/lib/audit/samples";
import { probeContractInterfaces, type CallProbeResult } from "@/lib/audit/simulator";
import type { Finding, PocResult, Report } from "@/lib/audit/types";
import { savePocRun, type PocRunResult } from "@/lib/poc-runs";
import {
  getBuildInfoFn,
  getDbInfo,
  getScan,
  queryRagKnowledgebaseFn,
  saveComprehensiveScanFn,
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

  // Input state
  const [selectedSampleId, setSelectedSampleId] = useState<string>("relic");
  const [contractBody, setContractBody] = useState<string>(defaultSample.body);
  const [contractLabel, setContractLabel] = useState<string>(defaultSample.label);

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

  // Local DB & RAG state
  const [isSavingDb, setIsSavingDb] = useState<boolean>(false);
  const [isSupabaseDbModalOpen, setIsSupabaseDbModalOpen] = useState<boolean>(false);
  const [dbSavedNotice, setDbSavedNotice] = useState<string | null>(null);
  // Which database the app is actually reading (from getDbInfo). Rendered
  // in the header so a wrong-project mismatch is visible at a glance.
  const [dbInfo, setDbInfo] = useState<{
    host: string | null;
    port: string | null;
    user: string | null;
    database: string | null;
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
    setContractBody(scan.body);
    setContractLabel(scan.label);
    setReport(scan.report);
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
    setContractBody(sample.body);
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
      const res = await analyzeAddress(clean, singleAddressChain);
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
      setContractBody(res.rawBody);
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
    setSelectedSampleId("custom");
    setContractBody(rawBody);
    setContractLabel(label);
    setReport(pipelineReport);
    setWorkbenchMode("audit");
    setActiveTab("findings");

    // If label or id looks like an address, try proxy detection
    const match = label.match(/0x[0-9a-fA-F]{40}/);
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

  // Single-PoC run with one LLM repair on compile failure. Returns the
  // final PoC result + the final test code (repaired when repair ran).
  // Repair failure is NOT a new verdict — the caller keeps the original
  // compile-error result, so a failed repair never hides the real error.
  const runSinglePocWithRepair = async (address: string, testCode: string) => {
    let poc = await runPocWithRpcRetries(getBackendUrl(), { address, testCode });
    if (poc.status === "error" && isPocCompileError(poc.logs ?? "")) {
      try {
        const repaired = await requestPocRepair({
          data: {
            contractName: report?.label ?? "TargetContract",
            originalCode: testCode,
            errorLogs: poc.logs ?? "",
            body: contractBody,
          },
        });
        testCode = repaired.fixedCode;
        poc = await runPocWithRpcRetries(getBackendUrl(), { address, testCode });
      } catch (repairErr) {
        console.warn("[Kiln] PoC repair failed:", repairErr);
      }
    }
    return { poc, testCode };
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
      const poc = await runPocWithRpcRetries(getBackendUrl(), { address: addr, testCode, chainId: singleAddressChain });
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
        source: testCode,
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
        setContractBody(content);
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
    const lines: string[] = [
      `# Kiln Security Audit Report: ${report.label}`,
      `Generated: ${new Date().toUTCString()}`,
      `Input Type: ${report.inputKind.toUpperCase()}`,
      `Overall Risk Score: ${report.riskScore}/100`,
      "",
      `## Executive Summary`,
      report.summary,
      "",
      `## Vulnerability Overview`,
      `- Critical: ${report.findings.filter((f) => f.severity === "critical").length}`,
      `- High: ${report.findings.filter((f) => f.severity === "high").length}`,
      `- Medium: ${report.findings.filter((f) => f.severity === "medium").length}`,
      `- Low: ${report.findings.filter((f) => f.severity === "low").length}`,
      `- Informational: ${report.findings.filter((f) => f.severity === "info").length}`,
      "",
      `## Findings Breakdown`,
    ];

    report.findings.forEach((f, idx) => {
      lines.push(`### [${f.severity.toUpperCase()}] ${idx + 1}. ${f.title}`);
      lines.push(`- **Detector**: \`${f.detector}\``);
      if (f.swc) lines.push(`- **Classification**: SWC-${f.swc}`);
      lines.push(`- **Confidence**: ${f.confidence}`);
      if (f.locationFn)
        lines.push(
          `- **Location**: \`${f.locationFn}\`${f.locationLine ? ` (Line ${f.locationLine})` : ""}`,
        );
      lines.push("");
      lines.push(`#### Description & Summary`);
      lines.push(f.summary);
      lines.push("");
      lines.push(`#### Technical Walkthrough`);
      lines.push(f.walkthrough);
      lines.push("");
      if (f.exploitSolidity) {
        lines.push(`#### Proof of Concept (Exploit Scenario)`);
        lines.push("```solidity");
        lines.push(f.exploitSolidity);
        lines.push("```");
        lines.push("");
      }
      if (f.remediationSolidity) {
        lines.push(`#### Recommended Remediation`);
        lines.push("```solidity");
        lines.push(f.remediationSolidity);
        lines.push("```");
        lines.push("");
      }
    });

    lines.push("---");
    lines.push("Static analysis report generated with Kiln. Code generation alone is not exploit reproduction.");
    return lines.join("\n");
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
