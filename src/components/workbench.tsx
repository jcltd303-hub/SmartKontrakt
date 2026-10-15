import { useState, useMemo, useEffect, useRef } from "react";
import { SAMPLES, type Sample } from "@/lib/audit/samples";
import { analyzeInput } from "@/lib/audit/engine";
import { looksLikeBytecode } from "@/lib/audit/bytecode";
import type { Report, Severity } from "@/lib/audit/types";
import type { ScanSummary } from "@/lib/audit/persist.server";
import { BatchPipeline } from "./batch-pipeline";
import { SUPPORTED_CHAINS, analyzeAddress, isValidEvmAddress } from "@/lib/audit/address-fetcher";
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
  // Mode state: Single audit vs Batch address pipeline
  const [workbenchMode, setWorkbenchMode] = useState<"audit" | "pipeline">("audit");

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
  const [activeTab, setActiveTab] = useState<"findings" | "surface" | "bytecode" | "report" | "history">("findings");
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
    try {
      const generated = analyzeInput(bodyToAnalyze, labelToAnalyze);
      setReport(generated);

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
    } catch (err) {
      console.error("[Kiln] Analysis failed:", err);
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
      setSelectedSampleId("custom");
      setContractBody(res.rawBody);
      setContractLabel(res.report.label);
      setReport(res.report);
      setActiveTab("findings");
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
            <div className="flex items-center bg-[#26231c] p-1 rounded-lg border border-[#3a3428] text-xs font-mono">
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
            </div>

            {workbenchMode === "audit" && (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="px-3 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-xs font-medium text-[#f4efe6] flex items-center gap-1.5 transition-colors"
                  title="Upload .sol or .hex file"
                >
                  <Upload className="w-3.5 h-3.5 text-[#e8a54b]" />
                  <span>Upload</span>
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
      </header>

      {/* Main Layout Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6">
        {workbenchMode === "pipeline" ? (
          <BatchPipeline onInspectItem={handleInspectPipelineItem} />
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* ================= Left Column: Contract Editor & Input ================= */}
            <section className="lg:col-span-5 flex flex-col gap-4">
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
            <div className="px-4 py-2.5 bg-[#26231c] border-b border-[#3a3428] flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 flex-1 min-w-0">
                <input
                  type="text"
                  value={contractLabel}
                  onChange={(e) => setContractLabel(e.target.value)}
                  className="bg-transparent border-none text-xs font-mono font-medium text-[#f4efe6] focus:outline-none focus:ring-1 focus:ring-[#e8a54b] rounded px-1.5 py-0.5 w-44 truncate"
                  placeholder="Contract name..."
                />
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
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
                      setReport(null);
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
        <section className="lg:col-span-7 flex flex-col gap-4">
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
                <Binary className="w-3.5 h-3.5" />
                <span>Bytecode & Opcodes</span>
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
                        className="p-2.5 bg-[#26231c] border border-[#3a3428] rounded-lg flex items-center justify-between font-mono text-xs"
                      >
                        <span className="text-[#e8a54b] font-bold">{sel.selector}</span>
                        <span className="text-[#a39886] truncate max-w-[200px]" title={sel.signature ?? ""}>
                          {sel.signature ?? "unknown()"}
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

              {/* Disassembly Stream View */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-xs font-mono font-bold text-[#a39886] uppercase tracking-wider">
                    Instruction Disassembly Stream
                  </h4>
                  <input
                    type="text"
                    placeholder="Search opcode (e.g. JUMP, CALL)..."
                    value={disasmFilter}
                    onChange={(e) => setDisasmFilter(e.target.value)}
                    className="bg-[#12110e] border border-[#3a3428] rounded px-2 py-0.5 text-xs text-[#f4efe6] font-mono focus:outline-none focus:border-[#e8a54b]"
                  />
                </div>

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
              </div>
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
</div>
  );
}
