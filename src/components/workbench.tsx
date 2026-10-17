import { useState, useMemo, useEffect, useRef } from "react";
import { SAMPLES, type Sample } from "@/lib/audit/samples";
import { analyzeInput } from "@/lib/audit/engine";
import { looksLikeBytecode, fullDisassembly } from "@/lib/audit/bytecode";
import type { Finding, Report, Severity } from "@/lib/audit/types";
import type { ScanSummary } from "@/lib/audit/persist.server";
import { BatchPipeline } from "./batch-pipeline";
import { CfgViewer } from "./cfg-viewer";
import { FoundryExport, downloadFile } from "./foundry-export";
import { FoundryLocalRun } from "./foundry-local-run";
import { AuditCertificate } from "./audit-certificate";
import { LocalDbRecords } from "./local-db-records";
import { RagKnowledgebase } from "./rag-knowledgebase";
import { SupabaseDbModal } from "./supabase-db-modal";
import { SUPPORTED_CHAINS, analyzeAddress, isValidEvmAddress } from "@/lib/audit/address-fetcher";
import { detectProxyArchitecture, type ProxyAnalysis } from "@/lib/audit/proxy-resolver";
import { probeContractInterfaces, type CallProbeResult } from "@/lib/audit/simulator";
import { requestAiReview, requestDeepAgentRound, requestPocRepair } from "@/lib/audit/ai.functions";
import { resolveFourbyte } from "@/lib/audit/fourbyte.functions";
import { applyFourbyteResults, fourbyteResultsFromReport } from "@/lib/audit/fourbyte";
import { getBackendUrl, isPocCompileError, runPocOnBackend } from "@/lib/audit/foundry-backend";
import type { PocResult } from "@/lib/audit/types";
import type { AiSecurityReview } from "@/lib/audit/ai-review.server";
import type {
  DeepAgentHypothesis,
  DeepAgentPriorResult,
} from "@/lib/audit/deep-agent.server";
import { saveComprehensiveScanFn, queryRagKnowledgebaseFn, getDbInfo } from "@/lib/scans.functions";
import type { StoredScan } from "@/lib/audit/persist.server";
import type { RagChunk } from "@/lib/audit/rag.server";
import {
  ShieldAlert,
  ShieldCheck,
  Flame,
  Info,
  Copy,
  Check,
  Search,
  FileCode,
  Binary,
  Layers,
  Zap,
  Trash2,
  Terminal,
  ChevronDown,
  ChevronRight,
  Code2,
  FileText,
  Clock,
  Upload,
  CheckCircle2,
  Crosshair,
  Bug,
  Globe,
  ListOrdered,
  Loader2,
  Award,
  Sparkles,
  GitBranch,
  Activity,
  ArrowRight,
  Shield,
  RefreshCw,
  Database,
  BookOpen,
  X,
} from "lucide-react";

interface WorkbenchProps {
  initialScans?: ScanSummary[];
}

const SEVERITY_CONFIG: Record<
  Severity,
  { label: string; badge: string; bg: string; border: string; text: string; dot: string }
> = {
  critical: {
    label: "Critical",
    badge: "bg-red-950/80 text-red-400 border-red-700/60",
    bg: "bg-red-950/20",
    border: "border-red-900/40",
    text: "text-red-400",
    dot: "bg-red-500",
  },
  high: {
    label: "High",
    badge: "bg-amber-950/80 text-amber-400 border-amber-700/60",
    bg: "bg-amber-950/20",
    border: "border-amber-900/40",
    text: "text-amber-400",
    dot: "bg-amber-500",
  },
  medium: {
    label: "Medium",
    badge: "bg-yellow-950/80 text-yellow-300 border-yellow-700/60",
    bg: "bg-yellow-950/20",
    border: "border-yellow-900/40",
    text: "text-yellow-400",
    dot: "bg-yellow-500",
  },
  low: {
    label: "Low",
    badge: "bg-blue-950/80 text-blue-300 border-blue-700/60",
    bg: "bg-blue-950/20",
    border: "border-blue-900/40",
    text: "text-blue-400",
    dot: "bg-blue-500",
  },
  info: {
    label: "Info",
    badge: "bg-stone-900 text-stone-300 border-stone-700/60",
    bg: "bg-stone-900/30",
    border: "border-stone-800",
    text: "text-stone-400",
    dot: "bg-stone-500",
  },
};

const defaultSample = SAMPLES[0] ?? { id: "relic", label: "RelicVault", blurb: "", body: "" };

function formatDate(iso: string): string {
  if (!iso) return "Recent";
  return iso.length >= 10 ? iso.slice(0, 10) : iso;
}

export function Workbench({ initialScans = [] }: WorkbenchProps) {
  // Mode state: Single audit vs Batch address pipeline vs Local DB Records vs RAG Knowledgebase
  const [workbenchMode, setWorkbenchMode] = useState<"audit" | "pipeline" | "records" | "rag">("audit");

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
    analyzeInput(defaultSample.body, defaultSample.label)
  );
  const [activeTab, setActiveTab] = useState<"findings" | "surface" | "bytecode" | "ai" | "probe" | "report" | "history">("findings");
  const [bytecodeSubView, setBytecodeSubView] = useState<"stream" | "cfg">("stream");

  // Advanced analysis state
  const [proxyInfo, setProxyInfo] = useState<ProxyAnalysis | null>(null);
  const [probes, setProbes] = useState<CallProbeResult[]>([]);
  const [isProbing, setIsProbing] = useState<boolean>(false);
  const [aiReview, setAiReview] = useState<AiSecurityReview | null>(null);
  const [pocResult, setPocResult] = useState<PocResult | null>(null);
  const [pocRunning, setPocRunning] = useState(false);
  const [pocSaved, setPocSaved] = useState(false);
  const [savedScanId, setSavedScanId] = useState<string | null>(null);
  const [isLoadingAi, setIsLoadingAi] = useState<boolean>(false);
  // Deep Agent state — agentic exploit search (see deep-agent.server.ts).
  const [deepAgentRunning, setDeepAgentRunning] = useState<boolean>(false);
  const [deepAgentStatus, setDeepAgentStatus] = useState<string | null>(null);
  const [deepAgentError, setDeepAgentError] = useState<string | null>(null);
  const [deepAgentRounds, setDeepAgentRounds] = useState<
    Array<{ round: number; hypotheses: Array<DeepAgentHypothesis & { pocResult: PocResult | null }> }>
  >([]);
  const [showCertificate, setShowCertificate] = useState<boolean>(false);
  const [findingTriage, setFindingTriage] = useState<Record<string, { status: "active" | "acknowledged" | "false_positive" | "remediated"; note?: string }>>({});

  // Local DB & RAG state
  const [isSavingDb, setIsSavingDb] = useState<boolean>(false);
  const [isSupabaseDbModalOpen, setIsSupabaseDbModalOpen] = useState<boolean>(false);
  const [dbSavedNotice, setDbSavedNotice] = useState<string | null>(null);
  // Which database the app is actually reading (from getDbInfo). Rendered
  // in the header so a wrong-project mismatch is visible at a glance.
  const [dbInfo, setDbInfo] = useState<{ host: string | null; port: string | null; user: string | null; database: string | null; error: string | null } | null>(null);
  useEffect(() => {
    let cancelled = false;
    void getDbInfo().then((info) => {
      if (!cancelled) setDbInfo(info);
    }).catch(() => {
      // getDbInfo returns { error } instead of throwing; a transport
      // failure just leaves the label hidden.
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
              (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
            )
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
        const updated = [newScan, ...prev.filter((s) => s.label !== labelToAnalyze || s.riskScore !== newScan.riskScore)].slice(0, 30);
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
          triageStates: Object.fromEntries(Object.entries(findingTriage).map(([k, v]) => [k, v.status])),
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
      const certHash = "0x" + Array.from({ length: 32 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, "0")).join("");
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
          triageStates: Object.fromEntries(Object.entries(findingTriage).map(([k, v]) => [k, v.status])),
          certHash,
          sourceOrigin: "workbench",
          indexToRag: andIndexRag,
        },
      });
      if (saved?.id) setSavedScanId(saved.id);
      setDbSavedNotice(andIndexRag ? "Saved to Supabase DB & Ingested to RAG KB!" : "Saved to Supabase DB!");
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
      const formatted: Record<string, { status: "active" | "acknowledged" | "false_positive" | "remediated" }> = {};
      for (const [k, v] of Object.entries(scan.triageStates)) {
        formatted[k] = { status: v as "active" | "acknowledged" | "false_positive" | "remediated" };
      }
      setFindingTriage(formatted);
    }
    setWorkbenchMode("audit");
    setActiveTab("findings");
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
    let poc = await runPocOnBackend(getBackendUrl(), { address, testCode });
    if (poc.status === "error" && isPocCompileError(poc.logs ?? "")) {
      try {
        const repaired = await requestPocRepair({ data: {
          contractName: report?.label ?? "TargetContract",
          originalCode: testCode,
          errorLogs: poc.logs ?? "",
          body: contractBody,
        } });
        testCode = repaired.fixedCode;
        poc = await runPocOnBackend(getBackendUrl(), { address, testCode });
      } catch (repairErr) {
        console.warn("[Kiln] PoC repair failed:", repairErr);
      }
    }
    return { poc, testCode };
  };

  // Request AI Threat Modeling & Foundry Test Suite (OpenRouter API)
  const handleTriggerAiReview = async () => {
    if (!report) return;
    setIsLoadingAi(true);
    try {
      const res = await requestAiReview({ data: {
        contractName: report.label,
        body: contractBody,
        findings: report.findings,
        fourbyte: fourbyteResultsFromReport(report),
      } });
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
          triageStates: Object.fromEntries(Object.entries(findingTriage).map(([k, v]) => [k, v.status])),
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
      setDeepAgentError("Fetch an on-chain address first — the Deep Agent proves hypotheses with fork PoCs.");
      return;
    }
    setDeepAgentRunning(true);
    setDeepAgentError(null);
    setDeepAgentRounds([]);
    setDeepAgentStatus("Round 1: proposing hypotheses…");
    const priorResults: DeepAgentPriorResult[] = [];
    const rounds: Array<{ round: number; hypotheses: Array<DeepAgentHypothesis & { pocResult: PocResult | null }> }> = [];
    try {
      for (let round = 1; round <= DEEP_AGENT_MAX_ROUNDS; round += 1) {
        // Confirmed hypotheses join the findings so the next round goes
        // deeper on the proven attack surface.
        const confirmedFindings: Finding[] = rounds.flatMap((r) =>
          r.hypotheses
            .filter((h) => h.pocResult?.status === "passed")
            .map((h, i) => ({
              id: `deep-${r.round}-${i}`,
              severity: h.severity,
              swc: null,
              title: h.title,
              confidence: "high" as const,
              detector: h.detector,
              summary: `Deep Agent confirmed on fork: ${h.hypothesis}`,
              walkthrough: "",
              exploitSolidity: h.foundryTestCode,
              remediationSolidity: "",
              locationFn: null,
              locationLine: null,
              snippet: "",
            })),
        );
        const res = await requestDeepAgentRound({ data: {
          contractName: report.label,
          body: contractBody,
          findings: [...report.findings, ...confirmedFindings],
          priorResults,
          round,
          fourbyte: fourbyteResultsFromReport(report),
        } });
        if (res.hypotheses.length === 0) {
          setDeepAgentStatus(
            res.stopReason
              ? `Search stopped: ${res.stopReason}`
              : "Search stopped: no new hypotheses.",
          );
          break;
        }
        const roundRun: { round: number; hypotheses: Array<DeepAgentHypothesis & { pocResult: PocResult | null }> } = {
          round,
          hypotheses: [],
        };
        rounds.push(roundRun);
        setDeepAgentRounds([...rounds]);
        let stoppedOnError = false;
        for (const h of res.hypotheses) {
          setDeepAgentStatus(`Round ${round}: running PoC for "${h.title}"…`);
          let testCode = h.foundryTestCode;
          let poc = await runPocOnBackend(getBackendUrl(), { address: addr, testCode });
          // Repair loop (same as the worker): a PoC that fails to
          // COMPILE gets ONE LLM repair + one re-run.
          if (poc.status === "error" && isPocCompileError(poc.logs ?? "")) {
            setDeepAgentStatus(`Round ${round}: PoC for "${h.title}" failed to compile — asking the model to repair it…`);
            try {
              const repaired = await requestPocRepair({ data: {
                contractName: report.label,
                originalCode: testCode,
                errorLogs: poc.logs ?? "",
                body: contractBody,
              } });
              testCode = repaired.fixedCode;
              poc = await runPocOnBackend(getBackendUrl(), { address: addr, testCode });
            } catch (repairErr) {
              setDeepAgentError(
                `PoC repair failed: ${repairErr instanceof Error ? repairErr.message : String(repairErr)} — stopping the search.`,
              );
              stoppedOnError = true;
              break;
            }
          }
          const outcome = poc.status === "passed" ? "confirmed" : poc.status === "failed" ? "refuted" : "error";
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
    return report.findings.filter((f) => {
      const matchesSeverity = severityFilter === "all" || f.severity === severityFilter;
      const q = findingSearch.toLowerCase().trim();
      const matchesSearch =
        !q ||
        f.title.toLowerCase().includes(q) ||
        f.detector.toLowerCase().includes(q) ||
        (f.swc && f.swc.toLowerCase().includes(q)) ||
        (f.locationFn && f.locationFn.toLowerCase().includes(q)) ||
        f.summary.toLowerCase().includes(q);
      return matchesSeverity && matchesSearch;
    });
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
      if (f.locationFn) lines.push(`- **Location**: \`${f.locationFn}\`${f.locationLine ? ` (Line ${f.locationLine})` : ""}`);
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
    lines.push("Audit verified with Kiln EVM Static Analysis Engine.");
    return lines.join("\n");
  };

  // Risk Score color helper
  const getRiskColor = (score: number) => {
    if (score >= 80) return { text: "text-red-400", bg: "bg-red-500", ring: "ring-red-500/30", label: "CRITICAL" };
    if (score >= 50) return { text: "text-amber-400", bg: "bg-amber-500", ring: "ring-amber-500/30", label: "HIGH RISK" };
    if (score >= 20) return { text: "text-yellow-400", bg: "bg-yellow-500", ring: "ring-yellow-500/30", label: "MEDIUM RISK" };
    if (score > 0) return { text: "text-blue-400", bg: "bg-blue-500", ring: "ring-blue-500/30", label: "LOW RISK" };
    return { text: "text-emerald-400", bg: "bg-emerald-500", ring: "ring-emerald-500/30", label: "CLEAN / NO HITS" };
  };

  const risk = report ? getRiskColor(report.riskScore) : { text: "text-stone-400", bg: "bg-stone-500", ring: "ring-stone-500/30", label: "PENDING" };

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

  return (
    <div className="min-h-screen bg-[#12110e] text-[#f4efe6] flex flex-col font-sans selection:bg-[#e8a54b]/30 selection:text-[#f4efe6]">
      {/* Hidden file input for Solidity/bytecode upload */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".sol,.hex,.bin,.txt"
        onChange={handleFileUpload}
        className="hidden"
      />

      {/* Top Banner Navigation */}
      <header className="border-b border-[#3a3428] bg-[#1c1a16]/90 backdrop-blur sticky top-0 z-40 px-4 sm:px-6 py-3">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center justify-between gap-3">
          {/* Logo & Identity */}
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-[#e8a54b] to-[#e25b45] p-0.5 shadow-lg shadow-[#e8a54b]/10 flex items-center justify-center">
              <div className="w-full h-full bg-[#12110e] rounded-[7px] flex items-center justify-center">
                <Flame className="w-5 h-5 text-[#e8a54b]" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-wider text-[#f4efe6] font-mono">KILN</span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-[#3a2c14] text-[#e8a54b] border border-[#e8a54b]/30 font-mono font-medium">
                  v2.4 EVM
                </span>
              </div>
              <p className="text-xs text-[#a39886]">Smart Contract & Bytecode Security Audit Workbench</p>
            </div>
          </div>

          {/* Mode Switcher & Controls */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Primary Mode Switcher */}
            <div className="flex w-full flex-wrap items-center bg-[#26231c] p-1 rounded-lg border border-[#3a3428] text-xs font-mono md:w-auto">
              <button
                onClick={() => setWorkbenchMode("audit")}
                className={`px-3 py-1 rounded-md font-medium transition-all flex items-center gap-1.5 ${
                  workbenchMode === "audit"
                    ? "bg-[#e8a54b] text-[#12110e] font-bold shadow"
                    : "text-[#a39886] hover:text-[#f4efe6]"
                }`}
              >
                <Code2 className="w-3.5 h-3.5" />
                <span>Workbench</span>
              </button>
              <button
                onClick={() => setWorkbenchMode("pipeline")}
                className={`px-3 py-1 rounded-md font-medium transition-all flex items-center gap-1.5 ${
                  workbenchMode === "pipeline"
                    ? "bg-[#e8a54b] text-[#12110e] font-bold shadow"
                    : "text-[#a39886] hover:text-[#f4efe6]"
                }`}
              >
                <ListOrdered className="w-3.5 h-3.5" />
                <span>Address Pipeline</span>
              </button>
              <button
                onClick={() => setWorkbenchMode("records")}
                className={`px-3 py-1 rounded-md font-medium transition-all flex items-center gap-1.5 ${
                  workbenchMode === "records"
                    ? "bg-[#e8a54b] text-[#12110e] font-bold shadow"
                    : "text-[#a39886] hover:text-[#f4efe6]"
                }`}
              >
                <Database className="w-3.5 h-3.5" />
                <span>Supabase Records</span>
              </button>
              <button
                onClick={() => setWorkbenchMode("rag")}
                className={`px-3 py-1 rounded-md font-medium transition-all flex items-center gap-1.5 ${
                  workbenchMode === "rag"
                    ? "bg-[#e8a54b] text-[#12110e] font-bold shadow"
                    : "text-[#a39886] hover:text-[#f4efe6]"
                }`}
              >
                <BookOpen className="w-3.5 h-3.5" />
                <span>RAG Knowledgebase</span>
              </button>
            </div>

            <button
              onClick={() => setIsSupabaseDbModalOpen(true)}
              className="px-2.5 py-1.5 rounded-lg border border-[#3a3428] bg-[#26231c] hover:bg-[#3a3428] text-xs font-mono text-[#e8a54b] flex items-center gap-1.5 transition-colors"
              title="Configure Supabase Database (SmartKontrakt)"
            >
              <Database className="w-3.5 h-3.5" />
              <span>Supabase Config</span>
            </button>
            {dbInfo && (
              <span
                className={`text-[11px] font-mono truncate ${dbInfo.error ? "text-red-400" : "text-[#a39886]"}`}
                title={dbInfo.error ?? `Database the app is reading: ${dbInfo.user}@${dbInfo.host}:${dbInfo.port}/${dbInfo.database}`}
              >
                {dbInfo.error
                  ? "DB: not configured — set DATABASE_URL in Vercel"
                  : `DB: ${dbInfo.user}@${dbInfo.host}`}
              </span>
            )}

            {workbenchMode === "audit" && (
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => handleSaveToLocalDb(true)}
                  disabled={isSavingDb}
                  className="px-3 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-xs font-medium text-[#f4efe6] flex items-center gap-1.5 transition-colors"
                  title="Save comprehensive audit dossier to Supabase PostgreSQL database and auto-index to RAG knowledgebase"
                >
                  {isSavingDb ? (
                    <Loader2 className="w-3.5 h-3.5 text-[#e8a54b] animate-spin" />
                  ) : (
                    <Database className="w-3.5 h-3.5 text-[#e8a54b]" />
                  )}
                  <span>Save to Supabase DB</span>
                </button>

                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="px-3 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-xs font-medium text-[#f4efe6] flex items-center gap-1.5 transition-colors"
                  title="Upload .sol or .hex file"
                >
                  <Upload className="w-3.5 h-3.5 text-[#e8a54b]" />
                  <span>Upload</span>
                </button>

                <button
                  onClick={() => setShowCertificate(true)}
                  className="px-3 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-xs font-medium text-[#f4efe6] flex items-center gap-1.5 transition-colors"
                  title="Open Official Audit Certificate & PDF"
                >
                  <Award className="w-3.5 h-3.5 text-[#e8a54b]" />
                  <span>Certificate</span>
                </button>

                <button
                  onClick={() => handleRunAnalysis()}
                  className="px-4 py-1.5 rounded-lg bg-gradient-to-r from-[#e8a54b] to-[#d97706] hover:brightness-110 text-[#12110e] text-xs font-bold font-mono tracking-wide flex items-center gap-1.5 shadow-md shadow-[#e8a54b]/20 transition-all active:scale-95"
                >
                  <Zap className="w-3.5 h-3.5 fill-current" />
                  <span>RUN AUDIT</span>
                </button>
              </div>
            )}
          </div>
        </div>

        {dbSavedNotice && (
          <div className="max-w-7xl mx-auto mt-2 px-3 py-1.5 bg-emerald-950/80 border border-emerald-800 text-emerald-300 text-xs font-mono rounded-lg flex items-center justify-between animate-fadeIn">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              {dbSavedNotice}
            </span>
            <button
              onClick={() => setDbSavedNotice(null)}
              className="text-[#746c60] hover:text-[#f4efe6]"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </header>

      {/* Main Layout Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6">
        <div hidden={workbenchMode !== "pipeline"}>
          <BatchPipeline onInspectItem={handleInspectPipelineItem} />
        </div>
        {workbenchMode === "pipeline" ? null : workbenchMode === "records" ? (
          <LocalDbRecords
            onLoadInWorkbench={handleLoadStoredScan}
            onNavigateToRag={() => setWorkbenchMode("rag")}
          />
        ) : workbenchMode === "rag" ? (
          <RagKnowledgebase
            onLoadContractInWorkbench={(body, label) => {
              setContractBody(body);
              setContractLabel(label);
              setWorkbenchMode("audit");
              handleRunAnalysis(body, label);
            }}
          />
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* ================= Left Column: Contract Editor & Input ================= */}
            <section className="lg:col-span-5 flex min-w-0 flex-col gap-4">
              {/* Single Address Fetcher Card */}
              <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-3.5 shadow-sm flex flex-col gap-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-[#a39886] uppercase tracking-wider flex items-center gap-1.5 font-mono">
                    <Globe className="w-3.5 h-3.5 text-[#e8a54b]" />
                    Fetch Contract by Address
                  </span>
                  <span className="text-[10px] text-[#746c60] font-mono">RPC + Sourcify</span>
                </div>
                <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                  <input
                    type="text"
                    placeholder="0x... EVM address"
                    value={singleAddress}
                    onChange={(e) => {
                      setSingleAddress(e.target.value);
                      setAddressFetchError(null);
                    }}
                    className="flex-1 bg-[#12110e] border border-[#3a3428] rounded px-3 py-1.5 text-xs font-mono text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
                  />
                  <select
                    value={singleAddressChain}
                    onChange={(e) => setSingleAddressChain(e.target.value)}
                    className="bg-[#26231c] border border-[#3a3428] rounded px-2.5 py-1.5 text-xs font-mono text-[#e8a54b] focus:outline-none cursor-pointer"
                  >
                    {SUPPORTED_CHAINS.map((c) => (
                      <option key={c.id} value={c.id} className="bg-[#1c1a16] text-[#f4efe6]">
                        {c.name}
                      </option>
                    ))}
                  </select>
                  <button
                    onClick={handleFetchSingleAddress}
                    disabled={isFetchingAddress || !singleAddress.trim()}
                    className="px-3.5 py-1.5 rounded bg-[#e8a54b] hover:brightness-110 text-[#12110e] text-xs font-bold font-mono flex items-center justify-center gap-1.5 disabled:opacity-50 transition-all shrink-0"
                  >
                    {isFetchingAddress ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
                    <span>Fetch</span>
                  </button>
                </div>
                {addressFetchError && (
                  <div className="text-[11px] text-red-400 font-mono bg-red-950/40 p-2 rounded border border-red-900/60 leading-relaxed">
                    {addressFetchError}
                  </div>
                )}
              </div>

              {/* Upgradeable Proxy Banner if detected */}
              {proxyInfo?.isProxy && proxyInfo.implementationAddress && (
                <div className="p-3.5 bg-purple-950/30 border border-purple-800/60 rounded-xl flex flex-col gap-2 font-mono text-xs shadow-sm">
                  <div className="flex items-center justify-between">
                    <span className="text-purple-300 font-bold flex items-center gap-1.5">
                      <Layers className="w-3.5 h-3.5 text-purple-400" />
                      {proxyInfo.proxyType} Upgradeable Proxy Detected
                    </span>
                    <span className="text-[10px] text-purple-400/80">EIP-1967 Storage Slot</span>
                  </div>
                  <div className="text-[11px] text-[#f4efe6] break-all">
                    Implementation: <span className="text-purple-200 font-bold">{proxyInfo.implementationAddress}</span>
                  </div>
                  {proxyInfo.adminAddress && (
                    <div className="text-[10px] text-[#a39886] truncate">
                      Proxy Admin Controller: {proxyInfo.adminAddress}
                    </div>
                  )}
                  <button
                    onClick={() => {
                      setSingleAddress(proxyInfo.implementationAddress!);
                      handleFetchSingleAddress();
                    }}
                    className="mt-1 px-3 py-1.5 rounded bg-purple-900/70 hover:bg-purple-800 text-purple-200 text-xs font-bold flex items-center justify-center gap-1.5 transition-all shadow"
                  >
                    <ArrowRight className="w-3.5 h-3.5" />
                    <span>Audit Implementation Target Contract</span>
                  </button>
                </div>
              )}
          {/* Sample Selectors Ribbon */}
          <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-3.5 shadow-sm">
            <div className="flex items-center justify-between mb-2.5">
              <span className="text-xs font-semibold text-[#a39886] uppercase tracking-wider flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-[#e8a54b]" />
                Sample Test Vectors
              </span>
              <span className="text-[11px] text-[#746c60]">Click to load</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {SAMPLES.map((s) => (
                <button
                  key={s.id}
                  onClick={() => handleSelectSample(s)}
                  className={`text-xs px-2.5 py-1.5 rounded-md font-mono border transition-all ${
                    selectedSampleId === s.id
                      ? "bg-[#3a2c14] border-[#e8a54b] text-[#e8a54b] font-medium shadow-sm"
                      : "bg-[#26231c] border-[#3a3428] text-[#a39886] hover:text-[#f4efe6] hover:bg-[#322d24]"
                  }`}
                  title={s.blurb}
                >
                  {s.label}
                </button>
              ))}
              <button
                onClick={() => {
                  setSelectedSampleId("blank");
                  setContractBody("");
                  setContractLabel("Custom Contract");
                }}
                className={`text-xs px-2.5 py-1.5 rounded-md font-mono border transition-all ${
                  selectedSampleId === "blank"
                    ? "bg-[#3a2c14] border-[#e8a54b] text-[#e8a54b]"
                    : "bg-[#26231c] border-[#3a3428] text-[#746c60] hover:text-[#f4efe6]"
                }`}
              >
                + Blank
              </button>
            </div>
          </div>

          {/* Editor Container */}
          <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl flex flex-col flex-1 shadow-sm overflow-hidden min-h-[500px]">
            {/* Editor Meta Bar */}
            <div className="px-4 py-2.5 bg-[#26231c] border-b border-[#3a3428] flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2 min-w-0">
                <input
                  type="text"
                  value={contractLabel}
                  onChange={(e) => setContractLabel(e.target.value)}
                  className="bg-transparent border-none text-xs font-mono font-medium text-[#f4efe6] focus:outline-none focus:ring-1 focus:ring-[#e8a54b] rounded px-1.5 py-0.5 w-44 truncate"
                  placeholder="Contract name..."
                />
                <span
                  className={`shrink-0 whitespace-nowrap text-[10px] font-mono px-2 py-0.5 rounded border ${
                    isBytecode
                      ? "bg-purple-950/40 text-purple-300 border-purple-800/60"
                      : "bg-emerald-950/40 text-emerald-300 border-emerald-800/60"
                  }`}
                >
                  {isBytecode ? "EVM Runtime Bytecode" : "Solidity Source"}
                </span>
              </div>

              <div className="flex items-center gap-2 text-xs text-[#a39886] font-mono">
                <span>{contractBody.length.toLocaleString()} chars</span>
                <span>•</span>
                <span>{contractBody.split("\n").length} lines</span>
              </div>
            </div>

            {/* Code Textarea with subtle styling */}
            <div className="relative flex-1 flex flex-col">
              <textarea
                value={contractBody}
                onChange={(e) => {
                  setSelectedSampleId("custom");
                  setContractBody(e.target.value);
                }}
                placeholder="// Paste Solidity contract or runtime bytecode (0x...)..."
                spellCheck={false}
                className="w-full flex-1 p-4 bg-[#12110e]/70 text-[#f4efe6] font-mono text-xs sm:text-[13px] leading-relaxed resize-none focus:outline-none border-none selection:bg-[#e8a54b]/30"
                style={{ tabSize: 4 }}
              />

              {/* Editor bottom bar */}
              <div className="p-3 bg-[#1c1a16] border-t border-[#3a3428] flex items-center justify-between gap-2">
                <span className="text-[11px] text-[#746c60] font-mono flex items-center gap-1">
                  <Terminal className="w-3.5 h-3.5 text-[#e8a54b]" />
                  <span>Press Run Audit to analyze AST & opcodes</span>
                </span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      setContractBody("");
                      setReport(analyzeInput("", "Untitled contract"));
                    }}
                    className="p-1.5 text-[#746c60] hover:text-[#e25b45] transition-colors"
                    title="Clear editor"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => copyToClipboard(contractBody, "input")}
                    className="p-1.5 text-[#a39886] hover:text-[#f4efe6] transition-colors flex items-center gap-1 text-xs font-mono"
                    title="Copy code"
                  >
                    {copiedKey === "input" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ================= Right Column: Security Analysis & Findings ================= */}
        <section className="lg:col-span-7 flex min-w-0 flex-col gap-4">
          {/* Executive Header / Scorecard */}
          {report && (
            <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 sm:p-5 shadow-sm">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#3a3428]">
                {/* Score & Rating */}
                <div className="flex items-center gap-4">
                  <div className="relative w-16 h-16 rounded-xl bg-[#26231c] border border-[#3a3428] flex flex-col items-center justify-center shadow-inner">
                    <span className="text-[10px] font-mono text-[#a39886] uppercase">RISK</span>
                    <span className={`text-2xl font-bold font-mono ${risk.text}`}>{report.riskScore}</span>
                    <div className="absolute -bottom-1 -right-1">
                      {report.riskScore >= 50 ? (
                        <ShieldAlert className="w-5 h-5 text-red-400 drop-shadow" />
                      ) : (
                        <ShieldCheck className="w-5 h-5 text-emerald-400 drop-shadow" />
                      )}
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-base font-bold text-[#f4efe6]">{report.label}</h2>
                      <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${risk.text} bg-[#26231c] border border-[#3a3428]`}>
                        {risk.label}
                      </span>
                    </div>
                    <p className="text-xs text-[#a39886] mt-0.5 max-w-md line-clamp-1">
                      {report.inventory.kindNote || "Analysis completed"}
                    </p>
                  </div>
                </div>

                {/* Severity Counters Bar */}
                <div className="flex items-center gap-1.5 bg-[#26231c] p-1.5 rounded-lg border border-[#3a3428]">
                  <div className="px-2 py-1 text-center font-mono">
                    <div className="text-[10px] text-[#a39886] uppercase">Crit</div>
                    <div className="text-xs font-bold text-red-400">
                      {report.findings.filter((f) => f.severity === "critical").length}
                    </div>
                  </div>
                  <div className="w-px h-6 bg-[#3a3428]" />
                  <div className="px-2 py-1 text-center font-mono">
                    <div className="text-[10px] text-[#a39886] uppercase">High</div>
                    <div className="text-xs font-bold text-amber-400">
                      {report.findings.filter((f) => f.severity === "high").length}
                    </div>
                  </div>
                  <div className="w-px h-6 bg-[#3a3428]" />
                  <div className="px-2 py-1 text-center font-mono">
                    <div className="text-[10px] text-[#a39886] uppercase">Med</div>
                    <div className="text-xs font-bold text-yellow-400">
                      {report.findings.filter((f) => f.severity === "medium").length}
                    </div>
                  </div>
                  <div className="w-px h-6 bg-[#3a3428]" />
                  <div className="px-2 py-1 text-center font-mono">
                    <div className="text-[10px] text-[#a39886] uppercase">Low</div>
                    <div className="text-xs font-bold text-blue-400">
                      {report.findings.filter((f) => f.severity === "low").length}
                    </div>
                  </div>
                </div>
              </div>

              {/* Summary Text */}
              <div className="pt-3 flex items-start gap-2 text-xs text-[#f4efe6]/90 leading-relaxed font-sans">
                <Info className="w-4 h-4 text-[#e8a54b] shrink-0 mt-0.5" />
                <span>{report.summary}</span>
              </div>
            </div>
          )}

          {/* Tab Navigation */}
          <div className="flex items-center justify-between border-b border-[#3a3428] pb-1 overflow-x-auto gap-2">
            <div className="flex items-center gap-1">
              <button
                onClick={() => setActiveTab("findings")}
                className={`px-3 py-2 text-xs font-mono font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                  activeTab === "findings"
                    ? "bg-[#1c1a16] text-[#e8a54b] border-t-2 border-[#e8a54b] font-semibold"
                    : "text-[#a39886] hover:text-[#f4efe6]"
                }`}
              >
                <Bug className="w-3.5 h-3.5" />
                <span>Findings ({report?.findings.length ?? 0})</span>
              </button>

              <button
                onClick={() => setActiveTab("surface")}
                className={`px-3 py-2 text-xs font-mono font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                  activeTab === "surface"
                    ? "bg-[#1c1a16] text-[#e8a54b] border-t-2 border-[#e8a54b] font-semibold"
                    : "text-[#a39886] hover:text-[#f4efe6]"
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>Surface ABI ({report?.inventory.functions.length ?? 0})</span>
              </button>

              <button
                onClick={() => setActiveTab("bytecode")}
                className={`px-3 py-2 text-xs font-mono font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                  activeTab === "bytecode"
                    ? "bg-[#1c1a16] text-[#e8a54b] border-t-2 border-[#e8a54b] font-semibold"
                    : "text-[#a39886] hover:text-[#f4efe6]"
                }`}
              >
                <GitBranch className="w-3.5 h-3.5" />
                <span>Bytecode & CFG</span>
              </button>

              <button
                onClick={() => {
                  setActiveTab("ai");
                  if (!aiReview) handleTriggerAiReview();
                }}
                className={`px-3 py-2 text-xs font-mono font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                  activeTab === "ai"
                    ? "bg-[#1c1a16] text-[#e8a54b] border-t-2 border-[#e8a54b] font-semibold"
                    : "text-[#a39886] hover:text-[#f4efe6]"
                }`}
              >
                <Sparkles className="w-3.5 h-3.5 text-[#e8a54b]" />
                <span>AI Threat & Foundry</span>
              </button>

              <button
                onClick={() => {
                  setActiveTab("probe");
                  if (probes.length === 0 && singleAddress) handleRunManualProbe();
                }}
                className={`px-3 py-2 text-xs font-mono font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                  activeTab === "probe"
                    ? "bg-[#1c1a16] text-[#e8a54b] border-t-2 border-[#e8a54b] font-semibold"
                    : "text-[#a39886] hover:text-[#f4efe6]"
                }`}
              >
                <Activity className="w-3.5 h-3.5" />
                <span>State Probe ({probes.filter((p) => p.success).length})</span>
              </button>

              <button
                onClick={() => setActiveTab("report")}
                className={`px-3 py-2 text-xs font-mono font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                  activeTab === "report"
                    ? "bg-[#1c1a16] text-[#e8a54b] border-t-2 border-[#e8a54b] font-semibold"
                    : "text-[#a39886] hover:text-[#f4efe6]"
                }`}
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Full Report</span>
              </button>

              <button
                onClick={() => setActiveTab("history")}
                className={`px-3 py-2 text-xs font-mono font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                  activeTab === "history"
                    ? "bg-[#1c1a16] text-[#e8a54b] border-t-2 border-[#e8a54b] font-semibold"
                    : "text-[#a39886] hover:text-[#f4efe6]"
                }`}
              >
                <Clock className="w-3.5 h-3.5" />
                <span>Scans ({scanHistory.length})</span>
              </button>
            </div>

            {/* Quick Export Button */}
            {report && (
              <button
                onClick={() => copyToClipboard(generateMarkdownReport(), "md-report")}
                className="text-xs px-2.5 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#a39886] hover:text-[#f4efe6] font-mono flex items-center gap-1 transition-colors"
                title="Copy Full Markdown Report"
              >
                {copiedKey === "md-report" ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span>Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3 text-[#e8a54b]" />
                    <span>Copy MD</span>
                  </>
                )}
              </button>
            )}
          </div>

          {/* ================= Tab 1: Findings ================= */}
          {activeTab === "findings" && (
            <div className="flex flex-col gap-3">
              {/* Filter and Search Bar */}
              <div className="flex flex-wrap items-center justify-between gap-2 bg-[#1c1a16] p-2.5 rounded-lg border border-[#3a3428]">
                {/* Severity filter pills */}
                <div className="flex items-center gap-1 flex-wrap">
                  {(["all", "critical", "high", "medium", "low", "info"] as const).map((sev) => {
                    const count =
                      sev === "all"
                        ? report?.findings.length ?? 0
                        : report?.findings.filter((f) => f.severity === sev).length ?? 0;
                    return (
                      <button
                        key={sev}
                        onClick={() => setSeverityFilter(sev)}
                        className={`text-xs px-2 py-0.5 rounded font-mono capitalize transition-all ${
                          severityFilter === sev
                            ? "bg-[#e8a54b] text-[#12110e] font-bold"
                            : "bg-[#26231c] text-[#a39886] hover:text-[#f4efe6]"
                        }`}
                      >
                        {sev} ({count})
                      </button>
                    );
                  })}
                </div>

                {/* Search input */}
                <div className="relative w-44 sm:w-56">
                  <Search className="w-3.5 h-3.5 text-[#746c60] absolute left-2.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    placeholder="Filter findings..."
                    value={findingSearch}
                    onChange={(e) => setFindingSearch(e.target.value)}
                    className="w-full bg-[#12110e] border border-[#3a3428] rounded-md pl-8 pr-2.5 py-1 text-xs text-[#f4efe6] placeholder-[#746c60] focus:outline-none focus:border-[#e8a54b]"
                  />
                </div>
              </div>

              {/* Findings List */}
              {filteredFindings.length === 0 ? (
                <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-8 text-center flex flex-col items-center justify-center gap-3">
                  <ShieldCheck className="w-10 h-10 text-emerald-400/80" />
                  <h3 className="text-sm font-semibold text-[#f4efe6]">No Matching Vulnerabilities Found</h3>
                  <p className="text-xs text-[#a39886] max-w-md">
                    {findingSearch || severityFilter !== "all"
                      ? "Try loosening your severity filter or search terms."
                      : "None of the active security heuristics matched this contract. Always inspect the surface map manually before deployment."}
                  </p>
                </div>
              ) : (
                filteredFindings.map((finding) => {
                  const cfg = SEVERITY_CONFIG[finding.severity] ?? SEVERITY_CONFIG.info;
                  const isExpanded = Boolean(expandedFindings[finding.id]);

                  return (
                    <div
                      key={finding.id}
                      className={`border rounded-xl transition-all overflow-hidden ${
                        isExpanded ? `${cfg.border} bg-[#1c1a16]` : "border-[#3a3428] bg-[#1c1a16] hover:border-[#4d4536]"
                      }`}
                    >
                      {/* Finding Card Header */}
                      <button
                        onClick={() =>
                          setExpandedFindings((prev) => ({ ...prev, [finding.id]: !prev[finding.id] }))
                        }
                        className="w-full text-left p-3.5 flex items-start justify-between gap-3 focus:outline-none"
                      >
                        <div className="flex items-start gap-2.5 flex-1 min-w-0">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider shrink-0 border ${cfg.badge}`}
                          >
                            {cfg.label}
                          </span>

                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <h3 className="text-sm font-semibold text-[#f4efe6]">{finding.title}</h3>
                              {finding.swc && (
                                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#26231c] text-[#e8a54b] border border-[#3a3428]">
                                  SWC-{finding.swc}
                                </span>
                              )}
                              <span className="text-[10px] font-mono text-[#746c60]">
                                Conf: {finding.confidence}
                              </span>
                            </div>

                            <p className="text-xs text-[#a39886] mt-1 line-clamp-2">{finding.summary}</p>
                          </div>
                        </div>

                        <div className="flex items-center gap-2 shrink-0 pt-1">
                          {finding.locationFn && (
                            <span className="text-[11px] font-mono text-[#e8a54b] bg-[#3a2c14] px-2 py-0.5 rounded hidden sm:inline-block">
                              {finding.locationFn}
                              {finding.locationLine ? `:${finding.locationLine}` : ""}
                            </span>
                          )}
                          {isExpanded ? (
                            <ChevronDown className="w-4 h-4 text-[#a39886]" />
                          ) : (
                            <ChevronRight className="w-4 h-4 text-[#a39886]" />
                          )}
                        </div>
                      </button>

                      {/* Finding Expanded Details */}
                      {isExpanded && (
                        <div className="px-4 pb-4 pt-1 border-t border-[#3a3428] bg-[#12110e]/40 flex flex-col gap-3.5 text-xs">
                          {/* Location / Code Snippet */}
                          {finding.snippet && (
                            <div>
                              <div className="flex items-center justify-between text-[11px] font-mono text-[#a39886] mb-1">
                                <span>Vulnerable Code Line:</span>
                                {finding.locationLine && <span>Line {finding.locationLine}</span>}
                              </div>
                              <div className="p-3 bg-[#12110e] rounded-lg border border-[#3a3428] font-mono text-xs overflow-x-auto text-red-300">
                                <pre>{finding.snippet}</pre>
                              </div>
                            </div>
                          )}

                          {/* Technical Walkthrough */}
                          <div>
                            <span className="text-[11px] font-mono text-[#a39886] uppercase tracking-wider block mb-1">
                              Exploit Mechanics & Walkthrough:
                            </span>
                            <div className="p-3 bg-[#26231c]/50 rounded-lg border border-[#3a3428] text-[#f4efe6] leading-relaxed">
                              {finding.walkthrough}
                            </div>
                          </div>

                          {/* Attack PoC Solidity */}
                          {finding.exploitSolidity && (
                            <div>
                              <div className="flex items-center justify-between text-[11px] font-mono text-[#a39886] mb-1">
                                <span className="flex items-center gap-1.5 text-red-400">
                                  <Crosshair className="w-3.5 h-3.5" />
                                  Attack Contract (PoC):
                                </span>
                                <button
                                  onClick={() => copyToClipboard(finding.exploitSolidity, `poc-${finding.id}`)}
                                  className="flex items-center gap-1 text-[10px] text-[#e8a54b] hover:underline"
                                >
                                  {copiedKey === `poc-${finding.id}` ? (
                                    <Check className="w-3 h-3 text-emerald-400" />
                                  ) : (
                                    <Copy className="w-3 h-3" />
                                  )}
                                  <span>Copy PoC</span>
                                </button>
                              </div>
                              <div className="p-3 bg-[#12110e] rounded-lg border border-red-950 font-mono text-xs text-red-200 overflow-x-auto">
                                <pre>{finding.exploitSolidity}</pre>
                              </div>
                            </div>
                          )}

                          {/* Remediation Solidity */}
                          {finding.remediationSolidity && (
                            <div>
                              <div className="flex items-center justify-between text-[11px] font-mono text-[#a39886] mb-1">
                                <span className="flex items-center gap-1.5 text-emerald-400">
                                  <CheckCircle2 className="w-3.5 h-3.5" />
                                  Recommended Fix (Remediation):
                                </span>
                                <button
                                  onClick={() => copyToClipboard(finding.remediationSolidity, `fix-${finding.id}`)}
                                  className="flex items-center gap-1 text-[10px] text-[#e8a54b] hover:underline"
                                >
                                  {copiedKey === `fix-${finding.id}` ? (
                                    <Check className="w-3 h-3 text-emerald-400" />
                                  ) : (
                                    <Copy className="w-3 h-3" />
                                  )}
                                  <span>Copy Fix</span>
                                </button>
                              </div>
                              <div className="p-3 bg-[#12110e] rounded-lg border border-emerald-950 font-mono text-xs text-emerald-300 overflow-x-auto">
                                <pre>{finding.remediationSolidity}</pre>
                              </div>
                            </div>
                          )}

                          {/* Auditor Triage Selector */}
                          <div className="pt-2 border-t border-[#3a3428] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] font-mono">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <span className="text-[#a39886] text-[10px] uppercase font-bold">Auditor Triage:</span>
                              {(["active", "acknowledged", "false_positive", "remediated"] as const).map((st) => {
                                const current = findingTriage[finding.id]?.status ?? "active";
                                const isCur = current === st;
                                return (
                                  <button
                                    key={st}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setFindingTriage((prev) => ({
                                        ...prev,
                                        [finding.id]: { ...prev[finding.id], status: st },
                                      }));
                                    }}
                                    className={`px-2 py-0.5 rounded text-[10px] capitalize transition-colors ${
                                      isCur
                                        ? st === "remediated"
                                          ? "bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold"
                                          : st === "false_positive"
                                          ? "bg-purple-950 text-purple-300 border border-purple-800 font-bold"
                                          : st === "acknowledged"
                                          ? "bg-amber-950 text-amber-300 border border-amber-800 font-bold"
                                          : "bg-red-950 text-red-300 border border-red-800 font-bold"
                                        : "bg-[#26231c] text-[#746c60] hover:text-[#f4efe6] border border-[#3a3428]"
                                    }`}
                                  >
                                    {st.replace("_", " ")}
                                  </button>
                                );
                              })}
                            </div>
                            <div className="flex items-center gap-2">
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleOpenRagForFinding(finding);
                                }}
                                className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] text-[#e8a54b] hover:text-[#f4efe6] border border-[#3a3428] transition-colors text-[10px] font-mono shrink-0 shadow-sm"
                                title="Query local RAG knowledgebase for historical occurrences, exploit vectors, and fixes"
                              >
                                <BookOpen className="w-3 h-3 text-[#e8a54b]" />
                                <span>Ask RAG About Vuln</span>
                              </button>
                              <span className="text-[10px] text-[#746c60] hidden sm:inline">Status saved</span>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          )}

          {/* ================= Tab 2: Surface ABI ================= */}
          {activeTab === "surface" && (
            <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 flex flex-col gap-5">
              {/* Functions Surface */}
              <div>
                <h3 className="text-xs font-mono font-bold text-[#e8a54b] uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                  <Code2 className="w-3.5 h-3.5" />
                  Discovered Functions ({report?.inventory.functions.length ?? 0})
                </h3>
                {report?.inventory.functions.length === 0 ? (
                  <p className="text-xs text-[#746c60]">No function declarations parsed in this source.</p>
                ) : (
                  <div className="border border-[#3a3428] rounded-lg overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-[#26231c] text-[#a39886] border-b border-[#3a3428]">
                        <tr>
                          <th className="p-2.5">Function Name</th>
                          <th className="p-2.5">Visibility</th>
                          <th className="p-2.5">Mutability</th>
                          <th className="p-2.5">Modifiers</th>
                          <th className="p-2.5">Parameters</th>
                          <th className="p-2.5">Line</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#3a3428]">
                        {report?.inventory.functions.map((fn, idx) => (
                          <tr key={idx} className="hover:bg-[#26231c]/50">
                            <td className="p-2.5 font-bold text-[#f4efe6]">{fn.name}</td>
                            <td className="p-2.5">
                              <span
                                className={`px-1.5 py-0.5 rounded text-[10px] ${
                                  fn.visibility === "external" || fn.visibility === "public"
                                    ? "bg-amber-950/60 text-amber-300 border border-amber-800"
                                    : "bg-[#26231c] text-[#a39886]"
                                }`}
                              >
                                {fn.visibility}
                              </span>
                            </td>
                            <td className="p-2.5 text-[#a39886]">{fn.mutability}</td>
                            <td className="p-2.5">
                              {fn.modifiers.length > 0 ? (
                                <span className="text-emerald-400">{fn.modifiers.join(", ")}</span>
                              ) : (
                                <span className="text-[#746c60]">—</span>
                              )}
                            </td>
                            <td className="p-2.5 text-[#a39886] max-w-[200px] truncate">{fn.params || "—"}</td>
                            <td className="p-2.5 text-[#746c60]">{fn.line ?? "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* State Variables */}
              <div>
                <h3 className="text-xs font-mono font-bold text-[#e8a54b] uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5" />
                  State Variables ({report?.inventory.stateVars.length ?? 0})
                </h3>
                {report?.inventory.stateVars.length === 0 ? (
                  <p className="text-xs text-[#746c60]">No state variables parsed.</p>
                ) : (
                  <div className="border border-[#3a3428] rounded-lg overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-[#26231c] text-[#a39886] border-b border-[#3a3428]">
                        <tr>
                          <th className="p-2.5">Variable Name</th>
                          <th className="p-2.5">Type</th>
                          <th className="p-2.5">Visibility</th>
                          <th className="p-2.5">Constant/Immutable</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#3a3428]">
                        {report?.inventory.stateVars.map((v, idx) => (
                          <tr key={idx} className="hover:bg-[#26231c]/50">
                            <td className="p-2.5 font-bold text-[#f4efe6]">{v.name}</td>
                            <td className="p-2.5 text-blue-300">{v.typeName}</td>
                            <td className="p-2.5 text-[#a39886]">{v.visibility}</td>
                            <td className="p-2.5">
                              {v.constOrImmutable ? (
                                <span className="text-emerald-400">Yes</span>
                              ) : (
                                <span className="text-[#746c60]">No</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Function Selectors */}
              <div>
                <h3 className="text-xs font-mono font-bold text-[#e8a54b] uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                  <Binary className="w-3.5 h-3.5" />
                  4-Byte Function Selectors ({report?.inventory.selectors.length ?? 0})
                </h3>
                {report?.inventory.selectors.length === 0 ? (
                  <p className="text-xs text-[#746c60]">No 4-byte selectors resolved.</p>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {report?.inventory.selectors.map((sel, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 bg-[#26231c] border border-[#3a3428] rounded-lg font-mono text-xs"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-[#e8a54b] font-bold">{sel.selector}</span>
                          <span className="text-[#a39886] truncate max-w-[200px]" title={sel.signature ?? ""}>
                            {sel.signature ?? "unknown()"}
                          </span>
                        </div>
                        {sel.signatures && sel.signatures.length > 1 && (
                          <details className="mt-1">
                            <summary className="cursor-pointer text-[11px] text-[#e8a54b]">
                              +{sel.signatures.length - 1} more {sel.signatures.length - 1 === 1 ? "signature" : "signatures"}
                            </summary>
                            <div className="mt-1 flex flex-col gap-0.5 text-[11px] text-[#a39886]">
                              {sel.signatures.slice(1).map((s) => (
                                <span key={s} title={s}>{s}</span>
                              ))}
                            </div>
                          </details>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Event Signatures (4byte) — only resolved topics shown;
                  analyzeBytecode also records unresolved PUSH32 candidates,
                  which enrichment fills when the table knows them. */}
              <div>
                <h3 className="text-xs font-mono font-bold text-[#e8a54b] uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                  <Binary className="w-3.5 h-3.5" />
                  32-Byte Event Signatures ({(report?.inventory.topics ?? []).filter((t) => t.signature).length})
                </h3>
                {(report?.inventory.topics ?? []).filter((t) => t.signature).length === 0 ? (
                  <p className="text-xs text-[#746c60]">No event topics resolved.</p>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {(report?.inventory.topics ?? []).filter((t) => t.signature).map((t, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 bg-[#26231c] border border-[#3a3428] rounded-lg flex items-center justify-between font-mono text-xs"
                      >
                        <span className="text-[#e8a54b] font-bold truncate max-w-[180px]" title={t.topic}>
                          {t.topic}
                        </span>
                        <span className="text-[#a39886] truncate max-w-[200px]" title={t.signature ?? ""}>
                          {t.signature ?? "unknown()"}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ================= Tab 3: Bytecode & Disassembly ================= */}
          {activeTab === "bytecode" && (
            <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 flex flex-col gap-4">
              {/* Bytecode Meta Stats */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                <div className="p-3 bg-[#26231c] border border-[#3a3428] rounded-lg text-center font-mono">
                  <span className="text-[10px] text-[#a39886] uppercase block">BYTECODE SIZE</span>
                  <span className="text-base font-bold text-[#f4efe6]">
                    {report?.inventory.bytecodeBytes ?? (contractBody.startsWith("0x") ? (contractBody.length - 2) / 2 : "N/A")} B
                  </span>
                </div>
                <div className="p-3 bg-[#26231c] border border-[#3a3428] rounded-lg text-center font-mono">
                  <span className="text-[10px] text-[#a39886] uppercase block">BASIC BLOCKS</span>
                  <span className="text-base font-bold text-amber-400">
                    {report?.inventory.basicBlocks ?? "Inferred"}
                  </span>
                </div>
                <div className="p-3 bg-[#26231c] border border-[#3a3428] rounded-lg text-center font-mono">
                  <span className="text-[10px] text-[#a39886] uppercase block">PROXY TYPE</span>
                  <span className="text-sm font-bold text-purple-300 truncate block">
                    {report?.inventory.proxy ?? "None / Direct"}
                  </span>
                </div>
                <div className="p-3 bg-[#26231c] border border-[#3a3428] rounded-lg text-center font-mono">
                  <span className="text-[10px] text-[#a39886] uppercase block">OPCODES PARSED</span>
                  <span className="text-base font-bold text-emerald-400">
                    {report?.inventory.opcodes.reduce((acc, o) => acc + o.count, 0) || disasmLines.length}
                  </span>
                </div>
              </div>

              {/* Critical Security Opcodes Table */}
              <div>
                <h4 className="text-xs font-mono font-bold text-[#e8a54b] uppercase tracking-wider mb-2">
                  Sensitive Opcode Occurrences
                </h4>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-xs">
                  {[
                    { name: "DELEGATECALL", hex: "0xf4", risk: "Critical" },
                    { name: "SELFDESTRUCT", hex: "0xff", risk: "Critical" },
                    { name: "ORIGIN", hex: "0x32", risk: "High" },
                    { name: "CALL", hex: "0xf1", risk: "Medium" },
                    { name: "CREATE2", hex: "0xf5", risk: "Medium" },
                    { name: "SLOAD", hex: "0x54", risk: "State Read" },
                    { name: "SSTORE", hex: "0x55", risk: "State Write" },
                    { name: "REVERT", hex: "0xfd", risk: "Control" },
                  ].map((op) => {
                    const found = report?.inventory.opcodes.find((o) => o.name === op.name)?.count ?? 0;
                    return (
                      <div
                        key={op.name}
                        className={`p-2 rounded border flex items-center justify-between ${
                          found > 0
                            ? op.risk === "Critical"
                              ? "bg-red-950/40 border-red-800 text-red-300"
                              : "bg-amber-950/30 border-amber-800 text-amber-300"
                            : "bg-[#26231c] border-[#3a3428] text-[#746c60]"
                        }`}
                      >
                        <div>
                          <div className="font-bold">{op.name}</div>
                          <div className="text-[10px] opacity-70">{op.hex}</div>
                        </div>
                        <span className="text-sm font-bold font-mono">{found}</span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Disassembly Stream vs CFG View Toggle */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-1 bg-[#26231c] p-1 rounded-lg border border-[#3a3428]">
                    <button
                      onClick={() => setBytecodeSubView("stream")}
                      className={`px-2.5 py-1 rounded text-[11px] font-mono transition-colors ${
                        bytecodeSubView === "stream" ? "bg-[#e8a54b] text-[#12110e] font-bold" : "text-[#a39886] hover:text-[#f4efe6]"
                      }`}
                    >
                      Linear Disassembly
                    </button>
                    <button
                      onClick={() => setBytecodeSubView("cfg")}
                      className={`px-2.5 py-1 rounded text-[11px] font-mono transition-colors flex items-center gap-1 ${
                        bytecodeSubView === "cfg" ? "bg-[#e8a54b] text-[#12110e] font-bold" : "text-[#a39886] hover:text-[#f4efe6]"
                      }`}
                    >
                      <GitBranch className="w-3 h-3" />
                      <span>Interactive CFG Graph</span>
                    </button>
                  </div>

                  {bytecodeSubView === "stream" && (
                    <input
                      type="text"
                      placeholder="Search opcode (e.g. JUMP, CALL)..."
                      value={disasmFilter}
                      onChange={(e) => setDisasmFilter(e.target.value)}
                      className="bg-[#12110e] border border-[#3a3428] rounded px-2 py-0.5 text-xs text-[#f4efe6] font-mono focus:outline-none focus:border-[#e8a54b]"
                    />
                  )}
                </div>

                {bytecodeSubView === "cfg" ? (
                  <CfgViewer disassembly={cfgDisassembly} />
                ) : (
                  <div className="max-h-96 overflow-y-auto bg-[#12110e] border border-[#3a3428] rounded-lg p-3 font-mono text-xs text-[#a39886] leading-relaxed">
                    {disasmLines.length === 0 ? (
                      <p className="text-center py-6 text-[#746c60]">
                        No raw bytecode disassembly generated. Paste runtime hex (0x...) to view full opcode streams.
                      </p>
                    ) : (
                      disasmLines.map((line, idx) => {
                        const isDanger =
                          line.includes("DELEGATECALL") || line.includes("SELFDESTRUCT") || line.includes("ORIGIN");
                        const isCall = line.includes("CALL") || line.includes("STATICCALL");
                        return (
                          <div
                            key={idx}
                            className={`hover:bg-[#26231c] px-1 py-0.5 rounded ${
                              isDanger
                                ? "text-red-400 font-bold bg-red-950/20"
                                : isCall
                                ? "text-amber-300"
                                : "text-[#f4efe6]"
                            }`}
                          >
                            {line}
                          </div>
                        );
                      })
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ================= Tab: AI Threat Modeling & Foundry Exploit ================= */}
          {activeTab === "ai" && (
            <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-5 flex flex-col gap-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#3a3428]">
                <div>
                  <div className="flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-[#e8a54b]" />
                    <h3 className="text-sm font-bold font-mono text-[#f4efe6]">
                      OpenRouter AI Threat Modeling & Foundry Exploit Suite
                    </h3>
                  </div>
                  <p className="text-xs text-[#a39886] mt-0.5">
                    Analyzes economic game-theory, flash loan risks, and generates a runnable Foundry test suite
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleTriggerAiReview}
                    disabled={isLoadingAi}
                    className="px-3.5 py-1.5 rounded bg-[#e8a54b] hover:brightness-110 text-[#12110e] font-bold font-mono text-xs flex items-center gap-1.5 shadow transition-all disabled:opacity-50"
                  >
                    {isLoadingAi ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                    <span>{isLoadingAi ? "Analyzing..." : "Re-Analyze with OpenRouter"}</span>
                  </button>
                </div>
              </div>

              {isLoadingAi ? (
                <div className="p-12 text-center flex flex-col items-center justify-center gap-3">
                  <Loader2 className="w-8 h-8 text-[#e8a54b] animate-spin" />
                  <p className="text-xs font-mono text-[#a39886]">
                    Synthesizing economic threat model and Foundry test suite...
                  </p>
                </div>
              ) : aiReview ? (
                <div className="flex flex-col gap-4">
                  {/* Economic risk banner */}
                  <div className="p-3 bg-amber-950/20 border border-amber-900/60 rounded-lg flex items-start gap-2.5 font-mono text-xs">
                    <Shield className="w-4 h-4 text-[#e8a54b] shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold text-[#e8a54b]">Economic Risk Profile: </span>
                      <span className="text-[#f4efe6]">{aiReview.economicRiskSummary}</span>
                      <span className="text-[10px] text-[#746c60] ml-2">({aiReview.source === "openrouter" ? "OpenRouter Live Engine" : "Structured Baseline Template"})</span>
                    </div>
                  </div>

                  {/* Foundry Test Suite */}
                  <div>
                    <div className="flex items-center justify-between pb-1.5">
                      <span className="text-xs font-mono font-bold text-[#e8a54b] uppercase flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5" />
                        Foundry Exploit Verification Test (test/Exploit.t.sol)
                      </span>
                      <button
                        onClick={() => copyToClipboard(aiReview.foundryTestCode, "foundry-poc")}
                        className="text-xs font-mono text-[#e8a54b] hover:underline flex items-center gap-1"
                      >
                        {copiedKey === "foundry-poc" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>Copy test/Exploit.t.sol</span>
                      </button>
                    </div>
                    <div className="p-3.5 bg-[#12110e] rounded-lg border border-[#3a3428] font-mono text-xs text-amber-200 overflow-x-auto max-h-72">
                      <pre>{aiReview.foundryTestCode}</pre>
                    </div>
                    <FoundryExport
                      testCode={aiReview.foundryTestCode}
                      contractAddress={singleAddress}
                      contractName={report?.label ?? "Contract"}
                    />
                    <FoundryLocalRun
                      testCode={aiReview.foundryTestCode}
                      address={singleAddress}
                    />
                    {(pocRunning || pocResult) && (
                      <div className="mt-2 p-3 bg-[#12110e] rounded-lg border border-[#3a3428] flex flex-col gap-2">
                        <div className="flex items-center gap-1.5 text-xs font-mono font-bold text-[#e8a54b]">
                          <span>Auto PoC run{ pocRunning ? " — running on local backend…" : pocSaved ? " — saved to Supabase" : ""}</span>
                        </div>
                        {pocResult && (
                          <>
                            <p
                              className={`text-xs font-mono font-bold ${
                                pocResult.status === "passed"
                                  ? "text-emerald-400"
                                  : pocResult.status === "failed"
                                    ? "text-red-400"
                                    : "text-amber-300"
                              }`}
                            >
                              {pocResult.status === "passed"
                                ? `PoC PASSED — exploit reproduced on fork (${pocResult.durationMs}ms)`
                                : pocResult.status === "failed"
                                  ? `PoC FAILED — exploit did not reproduce on fork (${pocResult.durationMs}ms)`
                                  : pocResult.status === "skipped"
                                    ? "Auto PoC skipped"
                                    : pocResult.status === "backend_unreachable"
                                      ? "Backend unreachable — start it in Termux, then re-generate the review"
                                      : `Backend error: ${pocResult.error ?? "forge run failed"}`}
                            </p>
                            <pre className="max-h-64 overflow-y-auto bg-[#0a0908] border border-[#3a3428] rounded p-2 text-[11px] font-mono text-[#f4efe6] whitespace-pre-wrap">
                              {pocResult.logs || "(no output)"}
                            </pre>
                          </>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Threat Model Narrative */}
                  <div>
                    <div className="flex items-center justify-between pb-1.5">
                      <span className="text-xs font-mono font-bold text-[#a39886] uppercase">
                        Executive Threat Model Narrative
                      </span>
                      <button
                        onClick={() => copyToClipboard(aiReview.threatModelReport, "threat-md")}
                        className="text-xs font-mono text-[#a39886] hover:text-[#f4efe6] flex items-center gap-1"
                      >
                        {copiedKey === "threat-md" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>Copy Narrative</span>
                      </button>
                    </div>
                    <div className="p-4 bg-[#26231c]/60 rounded-lg border border-[#3a3428] text-xs font-mono leading-relaxed text-[#f4efe6] whitespace-pre-wrap max-h-80 overflow-y-auto">
                      {aiReview.threatModelReport}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-10 flex flex-col items-center gap-3">
                  <Sparkles className="w-8 h-8 text-[#e8a54b]" />
                  <p className="text-xs font-mono text-[#a39886] max-w-md">
                    Click below to generate a deep AI Threat Model and an executable Foundry test suite (`test/Exploit.t.sol`).
                  </p>
                  <button
                    onClick={handleTriggerAiReview}
                    className="px-4 py-2 rounded bg-[#e8a54b] text-[#12110e] font-bold font-mono text-xs shadow hover:brightness-110"
                  >
                    Generate AI Threat Model
                  </button>
                </div>
              )}

              {/* Deep Agent — agentic exploit search */}
              <div className="mt-6 border-t border-[#3a3428] pt-4 flex flex-col gap-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs font-mono font-bold text-[#e8a54b] uppercase flex items-center gap-1.5">
                    <Crosshair className="w-3.5 h-3.5" />
                    Deep Agent — agentic exploit search
                  </span>
                  <button
                    onClick={handleRunDeepAgent}
                    disabled={deepAgentRunning || !report}
                    className="px-3 py-1.5 rounded bg-[#e8a54b] text-[#12110e] font-bold font-mono text-xs shadow hover:brightness-110 disabled:opacity-50 flex items-center gap-1.5"
                  >
                    {deepAgentRunning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Crosshair className="w-3.5 h-3.5" />}
                    <span>{deepAgentRunning ? "Running…" : "Run Deep Agent"}</span>
                  </button>
                </div>
                <p className="text-[11px] font-mono text-[#a39886]">
                  Proposes hypotheses the static detectors missed, proves each with a fork PoC, and feeds the result back — confirmed findings drive the next round deeper. Max 3 rounds, 2 hypotheses each. Each PoC runs on the local backend (forge fork), same as the AI PoC run.
                </p>
                {deepAgentStatus && (
                  <p className="text-xs font-mono text-[#f4efe6]">{deepAgentStatus}</p>
                )}
                {deepAgentError && (
                  <p className="text-xs font-mono text-red-400">{deepAgentError}</p>
                )}
                {deepAgentRounds.flatMap((r) => r.hypotheses).filter((h) => h.pocResult?.status === "passed").length > 0 && (
                  <p className="text-xs font-mono font-bold text-emerald-400">
                    Confirmed on fork: {deepAgentRounds.flatMap((r) => r.hypotheses).filter((h) => h.pocResult?.status === "passed").length} new vulnerabilit{deepAgentRounds.flatMap((r) => r.hypotheses).filter((h) => h.pocResult?.status === "passed").length === 1 ? "y" : "ies"} the static detectors missed
                  </p>
                )}
                {deepAgentRounds.map((r) => (
                  <div key={r.round} className="flex flex-col gap-2">
                    <span className="text-[11px] font-mono font-bold text-[#a39886] uppercase">Round {r.round}</span>
                    {r.hypotheses.map((h, i) => (
                      <details key={i} className="bg-[#12110e] rounded-lg border border-[#3a3428] p-3">
                        <summary className="cursor-pointer text-xs font-mono font-bold text-[#f4efe6] flex items-center gap-2 flex-wrap">
                          <span>{h.title}</span>
                          <span className="text-[10px] text-[#746c60]">({h.detector} · {h.severity})</span>
                          {h.pocResult ? (
                            <span className={`text-[10px] font-bold ${h.pocResult.status === "passed" ? "text-emerald-400" : h.pocResult.status === "failed" ? "text-red-400" : "text-amber-300"}`}>
                              {h.pocResult.status === "passed" ? "CONFIRMED on fork" : h.pocResult.status === "failed" ? "refuted — did not reproduce" : `PoC ${h.pocResult.status}`}
                            </span>
                          ) : (
                            <span className="text-[10px] text-amber-300">running PoC…</span>
                          )}
                        </summary>
                        <p className="mt-2 text-[11px] font-mono text-[#a39886] whitespace-pre-wrap">{h.hypothesis}</p>
                        <div className="mt-2 flex items-center justify-between">
                          <span className="text-[10px] font-mono font-bold text-[#e8a54b] uppercase">PoC (test/Exploit.t.sol)</span>
                          <button
                            onClick={() => copyToClipboard(h.foundryTestCode, `deep-poc-${r.round}-${i}`)}
                            className="text-[11px] font-mono text-[#e8a54b] hover:underline flex items-center gap-1"
                          >
                            {copiedKey === `deep-poc-${r.round}-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            <span>Copy PoC</span>
                          </button>
                        </div>
                        <pre className="mt-1 max-h-64 overflow-y-auto bg-[#0a0908] border border-[#3a3428] rounded p-2 text-[11px] font-mono text-amber-200 whitespace-pre-wrap">{h.foundryTestCode}</pre>
                        {h.pocResult && (
                          <pre className="mt-2 max-h-48 overflow-y-auto bg-[#0a0908] border border-[#3a3428] rounded p-2 text-[11px] font-mono text-[#f4efe6] whitespace-pre-wrap">{h.pocResult.logs || "(no output)"}</pre>
                        )}
                      </details>
                    ))}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ================= Tab: On-Chain State Probes ================= */}
          {activeTab === "probe" && (
            <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-5 flex flex-col gap-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#3a3428]">
                <div>
                  <div className="flex items-center gap-2">
                    <Activity className="w-4 h-4 text-[#e8a54b]" />
                    <h3 className="text-sm font-bold font-mono text-[#f4efe6]">
                      On-Chain Interface & State Simulator
                    </h3>
                  </div>
                  <p className="text-xs text-[#a39886] mt-0.5">
                    Live eth_call query probes against standard ERC-20, Vault, and Admin view selectors
                  </p>
                </div>

                <button
                  onClick={handleRunManualProbe}
                  disabled={isProbing}
                  className="px-3.5 py-1.5 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] font-mono text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
                >
                  {isProbing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5 text-[#e8a54b]" />}
                  <span>Re-Probe RPC</span>
                </button>
              </div>

              {probes.length === 0 ? (
                <div className="text-center py-8 text-xs font-mono text-[#746c60] flex flex-col items-center gap-2">
                  <Activity className="w-6 h-6 text-[#746c60]" />
                  <p>No active probe results. Enter an EVM contract address in the top toolbar to query live on-chain state.</p>
                </div>
              ) : (
                <div className="border border-[#3a3428] rounded-lg overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs">
                    <thead className="bg-[#26231c] border-b border-[#3a3428] text-[#a39886]">
                      <tr>
                        <th className="p-2.5">Interface Selector</th>
                        <th className="p-2.5">Method Signature</th>
                        <th className="p-2.5">Status</th>
                        <th className="p-2.5">Decoded Value</th>
                        <th className="p-2.5">Raw Hex</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#3a3428] text-[#f4efe6]">
                      {probes.map((probe, idx) => (
                        <tr key={idx} className="hover:bg-[#26231c]/40">
                          <td className="p-2.5 font-bold text-[#e8a54b]">{probe.selector}</td>
                          <td className="p-2.5 font-bold">{probe.name}</td>
                          <td className="p-2.5">
                            {probe.success ? (
                              <span className="text-emerald-400 flex items-center gap-1 text-[11px]">
                                <CheckCircle2 className="w-3 h-3" />
                                Returned
                              </span>
                            ) : (
                              <span className="text-[#746c60] text-[11px] truncate max-w-[120px]" title={probe.error}>
                                Reverted
                              </span>
                            )}
                          </td>
                          <td className="p-2.5 font-bold text-blue-300 max-w-[200px] truncate">
                            {probe.decodedString || probe.decodedNumber || probe.decodedAddress || (probe.success ? "0x" : "—")}
                          </td>
                          <td className="p-2.5 text-[#746c60] text-[10px] max-w-[180px] truncate" title={probe.rawResult}>
                            {probe.rawResult || "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* ================= Tab 4: Full Report ================= */}
          {activeTab === "report" && (
            <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-5 flex flex-col gap-4 font-mono text-xs">
              <div className="flex items-center justify-between pb-3 border-b border-[#3a3428]">
                <div>
                  <h3 className="text-sm font-bold text-[#f4efe6]">Complete Audit Report (Markdown)</h3>
                  <p className="text-[11px] text-[#a39886]">Formal security finding documentation & summary</p>
                </div>
                <button
                  onClick={() => copyToClipboard(generateMarkdownReport(), "md-full")}
                  className="px-3 py-1.5 rounded bg-[#e8a54b] text-[#12110e] font-bold text-xs flex items-center gap-1.5 shadow"
                >
                  {copiedKey === "md-full" ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copy Report</span>
                </button>
              </div>

              <div className="bg-[#12110e] p-4 rounded-lg border border-[#3a3428] max-h-[500px] overflow-y-auto leading-relaxed text-[#f4efe6]">
                <pre className="whitespace-pre-wrap">{generateMarkdownReport()}</pre>
              </div>
            </div>
          )}

          {/* ================= Tab 5: Scan History ================= */}
          {activeTab === "history" && (
            <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 flex flex-col gap-3">
              <div className="flex items-center justify-between pb-2 border-b border-[#3a3428]">
                <h3 className="text-xs font-mono font-bold text-[#e8a54b] uppercase tracking-wider">
                  Audit History Archive ({scanHistory.length})
                </h3>
                <span className="text-[11px] text-[#746c60]">Persisted across sessions</span>
              </div>

              {scanHistory.length === 0 ? (
                <p className="text-xs text-[#746c60] text-center py-6">No audits archived yet.</p>
              ) : (
                <div className="divide-y divide-[#3a3428] flex flex-col">
                  {scanHistory.map((scan) => {
                    const r = getRiskColor(scan.riskScore);
                    return (
                      <div
                        key={scan.id}
                        className="py-3 flex items-center justify-between gap-3 hover:bg-[#26231c]/40 px-2 rounded-lg transition-colors"
                      >
                        <div className="flex items-center gap-3">
                          <span
                            className={`w-9 h-9 rounded-lg flex items-center justify-center font-mono font-bold text-xs ${r.bg} text-[#12110e]`}
                          >
                            {scan.riskScore}
                          </span>
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-xs text-[#f4efe6]">{scan.label}</span>
                              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#26231c] text-[#a39886]">
                                {scan.inputKind}
                              </span>
                            </div>
                            <div className="text-[11px] text-[#746c60] mt-0.5 flex items-center gap-2 font-mono">
                              <span>Crit: {scan.criticalCount}</span>
                              <span>•</span>
                              <span>High: {scan.highCount}</span>
                              <span>•</span>
                              <span>{formatDate(scan.createdAt)}</span>
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => {
                              const foundSample = SAMPLES.find((s) => s.label === scan.label);
                              if (foundSample) {
                                handleSelectSample(foundSample);
                              } else {
                                setContractLabel(scan.label);
                                handleRunAnalysis(contractBody, scan.label);
                              }
                              setActiveTab("findings");
                            }}
                            className="px-2.5 py-1 text-xs font-mono bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] rounded text-[#f4efe6]"
                          >
                            Load
                          </button>
                          <button
                            onClick={(e) => handleDeleteScan(scan.id, e)}
                            className="p-1 text-[#746c60] hover:text-[#e25b45]"
                            title="Remove scan"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </section>
      </div>
    )}
  </main>

  {/* Official Audit Certificate Printable Modal */}
  {showCertificate && (
    <AuditCertificate
      report={report}
      contractBody={contractBody}
      onClose={() => setShowCertificate(false)}
    />
  )}

  {/* Quick RAG Finding Intelligence Modal */}
  {ragModalFinding && (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn font-mono text-xs">
      <div className="bg-[#1c1a16] border border-[#3a3428] rounded-2xl max-w-2xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
        <div className="p-4 border-b border-[#3a3428] flex items-center justify-between bg-[#26231c]/60">
          <div className="flex items-center gap-2">
            <BookOpen className="w-4 h-4 text-[#e8a54b]" />
            <div>
              <h3 className="font-bold text-sm text-[#f4efe6]">
                RAG Knowledgebase Intelligence
              </h3>
              <p className="text-[11px] text-[#a39886] truncate max-w-md">
                Historical patterns & fixes for: {ragModalFinding.title}
              </p>
            </div>
          </div>
          <button
            onClick={() => setRagModalFinding(null)}
            className="p-1 rounded text-[#a39886] hover:text-[#f4efe6]"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-4 overflow-y-auto flex flex-col gap-3 flex-1">
          {isLoadingRagModal ? (
            <div className="py-12 text-center text-[#a39886] flex flex-col items-center gap-2">
              <Loader2 className="w-6 h-6 animate-spin text-[#e8a54b]" />
              <span>Querying local RAG knowledge vectors...</span>
            </div>
          ) : ragModalResults.length === 0 ? (
            <div className="py-8 text-center text-[#746c60] flex flex-col items-center gap-2">
              <BookOpen className="w-8 h-8 text-[#746c60]" />
              <span>No direct knowledgebase matches found for this detector yet.</span>
            </div>
          ) : (
            ragModalResults.map((chunk) => (
              <div key={chunk.id} className="p-3 bg-[#12110e] rounded-xl border border-[#3a3428] flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-[#e8a54b]/20 text-[#e8a54b] border border-[#e8a54b]/40">
                      {chunk.relevanceScore}% MATCH
                    </span>
                    <span className="font-bold text-[#f4efe6] text-xs">{chunk.title}</span>
                  </div>
                  <span className="text-[10px] text-[#746c60]">{chunk.category}</span>
                </div>
                <p className="text-[#a39886] text-[11px] leading-relaxed line-clamp-3">
                  {chunk.content}
                </p>
                {chunk.metadata?.remediationSolidity && (
                  <div className="mt-1 p-2.5 bg-[#1c1a16] rounded border border-emerald-950 text-emerald-300 text-[11px] overflow-x-auto">
                    <pre>{chunk.metadata.remediationSolidity}</pre>
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        <div className="p-3 border-t border-[#3a3428] flex items-center justify-between bg-[#26231c]/40">
          <button
            onClick={() => {
              setRagModalFinding(null);
              setWorkbenchMode("rag");
            }}
            className="text-xs text-[#e8a54b] hover:underline flex items-center gap-1"
          >
            <span>Open in Full RAG Knowledgebase</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setRagModalFinding(null)}
            className="px-3 py-1.5 rounded bg-[#26231c] text-[#f4efe6] text-xs hover:bg-[#3a3428]"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )}

  <SupabaseDbModal
    isOpen={isSupabaseDbModalOpen}
    onClose={() => setIsSupabaseDbModalOpen(false)}
  />
</div>
  );
}
