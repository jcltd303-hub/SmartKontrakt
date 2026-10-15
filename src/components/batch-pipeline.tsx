import { useState, useEffect, useRef, useMemo } from "react";
import {
  parseAddressList,
  analyzeAddress,
  SUPPORTED_CHAINS,
  type BatchItem,
} from "@/lib/audit/address-fetcher";
import {
  getStoredSupabaseConfig,
  saveStoredSupabaseConfig,
  testSupabaseConnection,
  saveBatchItemToSupabase,
  loadBatchFromSupabase,
  type SupabaseConfig,
} from "@/lib/supabase";
import type { Report } from "@/lib/audit/types";
import {
  Play,
  Pause,
  RotateCcw,
  Upload,
  Download,
  Database,
  Search,
  ExternalLink,
  Copy,
  Check,
  CheckCircle2,
  XCircle,
  Loader2,
  FileText,
  Sliders,
  RefreshCw,
  Eye,
} from "lucide-react";

interface BatchPipelineProps {
  onInspectItem: (report: Report, rawBody: string, label: string) => void;
}

const SAMPLE_BATCH_INPUT = `# High-profile EVM contracts for security analysis
0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D # Uniswap V2 Router02
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 # WETH9 Wrapped Ether
0xdAC17F958D2ee523a2206206994597C13D831ec7 # Tether USD (USDT)
0x6B175474E89094C44Da98b954EedeAC495271d0F # Dai Stablecoin (DAI)
0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7 # Curve.fi 3pool`;

export function BatchPipeline({ onInspectItem }: BatchPipelineProps) {
  // Input text state
  const [inputText, setInputText] = useState<string>(SAMPLE_BATCH_INPUT);
  const [selectedChainId, setSelectedChainId] = useState<string>("ethereum");
  const [delayMs, setDelayMs] = useState<number>(600);

  // Queue state
  const [queue, setQueue] = useState<BatchItem[]>(() => {
    if (typeof window === "undefined") return [];
    try {
      const saved = localStorage.getItem("kiln_active_batch_queue");
      if (saved) return JSON.parse(saved) as BatchItem[];
    } catch {
      // fallback
    }
    return parseAddressList(SAMPLE_BATCH_INPUT, "ethereum");
  });

  // Runner state
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [currentIndex, setCurrentIndex] = useState<number>(-1);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [filterQuery, setFilterQuery] = useState<string>("");

  // Supabase state
  const [supabaseCfg, setSupabaseCfg] = useState<SupabaseConfig>(getStoredSupabaseConfig());
  const [isSupabaseModalOpen, setIsSupabaseModalOpen] = useState<boolean>(false);
  const [supabaseStatusMsg, setSupabaseStatusMsg] = useState<{ ok: boolean; msg: string } | null>(null);
  const [isTestingSupabase, setIsTestingSupabase] = useState<boolean>(false);

  const isRunningRef = useRef<boolean>(false);
  isRunningRef.current = isRunning;
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Save queue to localStorage whenever it changes
  useEffect(() => {
    try {
      localStorage.setItem("kiln_active_batch_queue", JSON.stringify(queue));
    } catch {
      // ignore
    }
  }, [queue]);

  // Copy helper
  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Parse text into queue
  const handleLoadNewBatch = () => {
    const parsed = parseAddressList(inputText, selectedChainId);
    setQueue(parsed);
    setIsRunning(false);
    setCurrentIndex(-1);
  };

  // Upload multiline file
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setInputText(content);
        const parsed = parseAddressList(content, selectedChainId);
        setQueue(parsed);
        setIsRunning(false);
        setCurrentIndex(-1);
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  // Main Sequential Pipeline Loop
  const startPipeline = async () => {
    if (isRunning) return;
    setIsRunning(true);

    const activeChain = selectedChainId;

    for (let i = 0; i < queue.length; i++) {
      if (!isRunningRef.current) break;

      const item = queue[i];
      if (!item) continue;

      // Skip already completed unless user requested retry
      if (item.status === "completed") continue;

      setCurrentIndex(i);

      // 1. Mark as fetching/analyzing
      setQueue((prev) => {
        const copy = [...prev];
        const target = copy[i];
        if (target) {
          copy[i] = { ...target, status: "analyzing", error: undefined };
        }
        return copy;
      });

      try {
        // Fetch and analyze
        const result = await analyzeAddress(item.address, activeChain, item.label);
        const crit = result.report.findings.filter((f) => f.severity === "critical").length;
        const high = result.report.findings.filter((f) => f.severity === "high").length;

        const updatedItem: BatchItem = {
          ...item,
          status: "completed",
          inputKind: result.inputKind,
          rawBody: result.rawBody,
          bytecodeSize: result.report.inventory.bytecodeBytes ?? (result.rawBody.length / 2),
          riskScore: result.report.riskScore,
          findingsCount: result.report.findings.length,
          criticalCount: crit,
          highCount: high,
          report: result.report,
          completedAt: new Date().toISOString(),
        };

        // Update queue item
        setQueue((prev) => {
          const copy = [...prev];
          copy[i] = updatedItem;
          return copy;
        });

        // Sync to Supabase if configured
        if (supabaseCfg.enabled) {
          saveBatchItemToSupabase(updatedItem, supabaseCfg);
        }
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        setQueue((prev) => {
          const copy = [...prev];
          const target = copy[i];
          if (target) {
            copy[i] = {
              ...target,
              status: "failed",
              error: errMsg,
            };
          }
          return copy;
        });
      }

      // Respect rate-limiting delay between addresses
      if (delayMs > 0 && i < queue.length - 1 && isRunningRef.current) {
        await new Promise((r) => setTimeout(r, delayMs));
      }
    }

    setIsRunning(false);
    setCurrentIndex(-1);
  };

  const pausePipeline = () => {
    setIsRunning(false);
    isRunningRef.current = false;
  };

  // Resume or load from Supabase
  const handleResumeSupabase = async () => {
    if (!supabaseCfg.enabled) {
      alert("Please configure and enable your Supabase connection first.");
      setIsSupabaseModalOpen(true);
      return;
    }
    const remoteItems = await loadBatchFromSupabase(supabaseCfg);
    if (remoteItems.length > 0) {
      // Merge remote into queue
      setQueue((prev) => {
        const map = new Map<string, BatchItem>();
        prev.forEach((p) => map.set(p.address.toLowerCase(), p));
        remoteItems.forEach((r) => map.set(r.address.toLowerCase(), r));
        return Array.from(map.values());
      });
      alert(`Loaded ${remoteItems.length} audited contracts from Supabase.`);
    } else {
      alert("No prior audits found in Supabase table.");
    }
  };

  // Test Supabase connection
  const handleTestSupabase = async () => {
    setIsTestingSupabase(true);
    setSupabaseStatusMsg(null);
    const result = await testSupabaseConnection(supabaseCfg.url, supabaseCfg.anonKey, supabaseCfg.tableName);
    setIsTestingSupabase(false);
    setSupabaseStatusMsg({ ok: result.ok, msg: result.message });
  };

  // Save Supabase settings
  const handleSaveSupabaseConfig = () => {
    saveStoredSupabaseConfig(supabaseCfg);
    setIsSupabaseModalOpen(false);
  };

  // Export batch summary to CSV
  const exportCsv = () => {
    const headers = ["Address", "Label", "Status", "Risk Score", "Critical", "High", "Findings", "Chain", "Error", "Completed At"];
    const rows = queue.map((q) => [
      q.address,
      `"${q.label.replace(/"/g, '""')}"`,
      q.status,
      q.riskScore ?? "",
      q.criticalCount ?? 0,
      q.highCount ?? 0,
      q.findingsCount ?? 0,
      q.chainId,
      `"${(q.error ?? "").replace(/"/g, '""')}"`,
      q.completedAt ?? "",
    ]);

    const csvContent = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `kiln-batch-audit-${selectedChainId}-${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Export batch to JSON
  const exportJson = () => {
    const jsonString = JSON.stringify(queue, null, 2);
    const blob = new Blob([jsonString], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `kiln-batch-audit-${selectedChainId}-${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Progress calculations
  const total = queue.length;
  const completed = queue.filter((q) => q.status === "completed").length;
  const failed = queue.filter((q) => q.status === "failed").length;
  const pending = queue.filter((q) => q.status === "pending" || q.status === "analyzing").length;
  const percent = total > 0 ? Math.round((completed / total) * 100) : 0;

  const totalCrit = queue.reduce((acc, q) => acc + (q.criticalCount ?? 0), 0);
  const totalHigh = queue.reduce((acc, q) => acc + (q.highCount ?? 0), 0);

  // Filtered queue items
  const filteredQueue = useMemo(() => {
    if (!filterQuery.trim()) return queue;
    const q = filterQuery.toLowerCase().trim();
    return queue.filter(
      (item) =>
        item.address.toLowerCase().includes(q) ||
        item.label.toLowerCase().includes(q) ||
        item.status.toLowerCase().includes(q)
    );
  }, [queue, filterQuery]);

  const activeChainObj = SUPPORTED_CHAINS.find((c) => c.id === selectedChainId) ?? SUPPORTED_CHAINS[0]!;

  return (
    <div className="flex flex-col gap-6 font-sans">
      <input
        ref={fileInputRef}
        type="file"
        accept=".txt,.csv"
        onChange={handleFileUpload}
        className="hidden"
      />

      {/* Supabase Connection Modal */}
      {isSupabaseModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl max-w-lg w-full p-5 shadow-2xl flex flex-col gap-4 text-xs font-mono">
            <div className="flex items-center justify-between pb-2 border-b border-[#3a3428]">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-[#e8a54b]" />
                <h3 className="font-bold text-sm text-[#f4efe6]">Supabase Pipeline Persistence</h3>
              </div>
              <button
                onClick={() => setIsSupabaseModalOpen(false)}
                className="text-[#a39886] hover:text-[#f4efe6]"
              >
                ✕
              </button>
            </div>

            <p className="text-[#a39886] text-[11px] leading-relaxed font-sans">
              Connect your Supabase project to automatically persist batch audits in real-time, resume queues across devices, and archive findings. (Works out-of-the-box on Vercel deployment with no native drivers required).
            </p>

            <div className="flex flex-col gap-3">
              <div>
                <label className="text-[#a39886] text-[10px] uppercase block mb-1">Supabase Project URL</label>
                <input
                  type="text"
                  placeholder="https://xyzproject.supabase.co"
                  value={supabaseCfg.url}
                  onChange={(e) => setSupabaseCfg({ ...supabaseCfg, url: e.target.value })}
                  className="w-full bg-[#12110e] border border-[#3a3428] rounded px-3 py-1.5 text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
                />
              </div>

              <div>
                <label className="text-[#a39886] text-[10px] uppercase block mb-1">Supabase Anon / Service Key</label>
                <input
                  type="password"
                  placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6..."
                  value={supabaseCfg.anonKey}
                  onChange={(e) => setSupabaseCfg({ ...supabaseCfg, anonKey: e.target.value })}
                  className="w-full bg-[#12110e] border border-[#3a3428] rounded px-3 py-1.5 text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
                />
              </div>

              <div>
                <label className="text-[#a39886] text-[10px] uppercase block mb-1">Table Name</label>
                <input
                  type="text"
                  placeholder="kiln_batch_audits"
                  value={supabaseCfg.tableName}
                  onChange={(e) => setSupabaseCfg({ ...supabaseCfg, tableName: e.target.value })}
                  className="w-full bg-[#12110e] border border-[#3a3428] rounded px-3 py-1.5 text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
                />
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="enableSupabase"
                  checked={supabaseCfg.enabled}
                  onChange={(e) => setSupabaseCfg({ ...supabaseCfg, enabled: e.target.checked })}
                  className="rounded border-[#3a3428] accent-[#e8a54b]"
                />
                <label htmlFor="enableSupabase" className="text-[#f4efe6] text-xs cursor-pointer">
                  Enable active Supabase sync for batch pipeline
                </label>
              </div>

              {supabaseStatusMsg && (
                <div
                  className={`p-2.5 rounded border text-[11px] ${
                    supabaseStatusMsg.ok
                      ? "bg-emerald-950/40 text-emerald-300 border-emerald-800"
                      : "bg-red-950/40 text-red-300 border-red-800"
                  }`}
                >
                  {supabaseStatusMsg.msg}
                </div>
              )}
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-[#3a3428]">
              <button
                type="button"
                onClick={handleTestSupabase}
                disabled={isTestingSupabase || !supabaseCfg.url}
                className="px-3 py-1.5 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] flex items-center gap-1.5 disabled:opacity-50"
              >
                {isTestingSupabase ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5 text-[#e8a54b]" />}
                <span>Test Connection</span>
              </button>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setIsSupabaseModalOpen(false)}
                  className="px-3 py-1.5 rounded text-[#a39886] hover:text-[#f4efe6]"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleSaveSupabaseConfig}
                  className="px-4 py-1.5 rounded bg-[#e8a54b] text-[#12110e] font-bold"
                >
                  Save Config
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

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
                value={selectedChainId}
                onChange={(e) => setSelectedChainId(e.target.value)}
                className="bg-transparent border-none text-[#e8a54b] font-bold focus:outline-none cursor-pointer"
              >
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
          </div>
        </div>

        {/* Pipeline Control Toolbar & Progress */}
        <div className="bg-[#26231c] border border-[#3a3428] rounded-lg p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-4">
          {/* Main Action Buttons */}
          <div className="flex flex-wrap items-center gap-2">
            {!isRunning ? (
              <button
                onClick={startPipeline}
                disabled={queue.length === 0 || completed === total}
                className="px-4 py-2 rounded-lg bg-gradient-to-r from-[#e8a54b] to-[#d97706] text-[#12110e] text-xs font-bold font-mono tracking-wide flex items-center gap-1.5 shadow-md shadow-[#e8a54b]/20 transition-all active:scale-95 disabled:opacity-50"
              >
                <Play className="w-4 h-4 fill-current" />
                <span>{completed > 0 && completed < total ? "RESUME PIPELINE" : "START PIPELINE"}</span>
              </button>
            ) : (
              <button
                onClick={pausePipeline}
                className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-bold font-mono tracking-wide flex items-center gap-1.5 shadow transition-all active:scale-95"
              >
                <Pause className="w-4 h-4 fill-current" />
                <span>PAUSE</span>
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

            {supabaseCfg.enabled && (
              <button
                onClick={handleResumeSupabase}
                className="px-3 py-2 rounded-lg bg-[#1c1a16] hover:bg-[#322d24] border border-[#3a3428] text-xs font-mono text-[#e8a54b] flex items-center gap-1.5 transition-colors"
                title="Fetch previous audits stored in Supabase"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Resume Supabase</span>
              </button>
            )}

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
      </div>

      {/* Multiline Address Input Box & Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Multiline Text Ingestion */}
        <div className="lg:col-span-5 bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-[#e8a54b]" />
              <h3 className="text-xs font-mono font-bold text-[#f4efe6] uppercase">
                Input Addresses (1 per line)
              </h3>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <button
                onClick={() => fileInputRef.current?.click()}
                className="px-2.5 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[11px] font-mono text-[#f4efe6] flex items-center gap-1 transition-colors"
                title="Upload .txt or .csv"
              >
                <Upload className="w-3 h-3 text-[#e8a54b]" />
                <span>Upload .txt</span>
              </button>
              <button
                onClick={() => setInputText(SAMPLE_BATCH_INPUT)}
                className="px-2 py-1 text-[11px] font-mono text-[#a39886] hover:text-[#f4efe6]"
              >
                Reset Sample
              </button>
            </div>
          </div>

          <textarea
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder={`0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984 # Uniswap Token\n0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D`}
            spellCheck={false}
            className="w-full h-56 bg-[#12110e] border border-[#3a3428] rounded-lg p-3 font-mono text-xs text-[#f4efe6] focus:outline-none focus:border-[#e8a54b] leading-relaxed resize-none"
          />

          <div className="flex items-center justify-between text-xs font-mono text-[#a39886]">
            <span>
              Parsed {parseAddressList(inputText, selectedChainId).length} valid addresses
            </span>
            <button
              onClick={handleLoadNewBatch}
              className="px-3 py-1 rounded bg-[#e8a54b] text-[#12110e] font-bold text-xs hover:brightness-110 transition-all"
            >
              Apply to Queue
            </button>
          </div>
        </div>

        {/* Right: Batch Execution Table */}
        <div className="lg:col-span-7 bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 flex flex-col gap-3">
          <div className="flex items-center justify-between gap-2 flex-wrap pb-2 border-b border-[#3a3428]">
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-mono font-bold text-[#f4efe6] uppercase">
                Pipeline Queue ({queue.length})
              </h3>
              {isRunning && (
                <span className="flex items-center gap-1 text-[10px] text-[#e8a54b] font-mono bg-[#3a2c14] px-2 py-0.5 rounded border border-[#e8a54b]/30">
                  <Loader2 className="w-3 h-3 animate-spin" />
                  <span>Processing...</span>
                </span>
              )}
            </div>

            {/* Filter and Exports */}
            <div className="flex items-center gap-2 text-xs font-mono">
              <div className="relative w-36 sm:w-44">
                <Search className="w-3.5 h-3.5 text-[#746c60] absolute left-2 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Filter queue..."
                  value={filterQuery}
                  onChange={(e) => setFilterQuery(e.target.value)}
                  className="w-full bg-[#12110e] border border-[#3a3428] rounded pl-7 pr-2 py-0.5 text-xs text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
                />
              </div>

              <button
                onClick={exportCsv}
                disabled={queue.length === 0}
                className="px-2.5 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#a39886] hover:text-[#f4efe6] flex items-center gap-1"
                title="Export CSV"
              >
                <Download className="w-3 h-3" />
                <span>CSV</span>
              </button>

              <button
                onClick={exportJson}
                disabled={queue.length === 0}
                className="px-2.5 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#a39886] hover:text-[#f4efe6] flex items-center gap-1"
                title="Export JSON"
              >
                <Download className="w-3 h-3" />
                <span>JSON</span>
              </button>
            </div>
          </div>

          {/* Queue List Table */}
          <div className="border border-[#3a3428] rounded-lg overflow-x-auto max-h-[380px] overflow-y-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#26231c] text-[#a39886] border-b border-[#3a3428] sticky top-0 z-10">
                <tr>
                  <th className="p-2.5">#</th>
                  <th className="p-2.5">Address</th>
                  <th className="p-2.5">Label</th>
                  <th className="p-2.5">Status</th>
                  <th className="p-2.5 text-center">Risk</th>
                  <th className="p-2.5 text-center">Crit</th>
                  <th className="p-2.5 text-center">High</th>
                  <th className="p-2.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#3a3428]">
                {filteredQueue.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="p-6 text-center text-[#746c60]">
                      No contracts in queue. Paste addresses on the left or upload a file.
                    </td>
                  </tr>
                ) : (
                  filteredQueue.map((item, idx) => {
                    const isCurrent = idx === currentIndex && isRunning;
                    return (
                      <tr
                        key={item.id}
                        className={`hover:bg-[#26231c]/50 transition-colors ${
                          isCurrent ? "bg-[#3a2c14]/40" : ""
                        }`}
                      >
                        <td className="p-2.5 text-[#746c60]">{idx + 1}</td>
                        <td className="p-2.5">
                          <div className="flex items-center gap-1.5 font-bold text-[#f4efe6]">
                            <span title={item.address}>
                              {item.address.slice(0, 6)}...{item.address.slice(-4)}
                            </span>
                            <button
                              onClick={() => copyText(item.address, `copy-${item.id}`)}
                              className="text-[#746c60] hover:text-[#e8a54b]"
                              title="Copy full address"
                            >
                              {copiedKey === `copy-${item.id}` ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                            <a
                              href={`${activeChainObj.blockExplorer}/address/${item.address}`}
                              target="_blank"
                              rel="noreferrer"
                              className="text-[#746c60] hover:text-[#e8a54b]"
                              title="View on block explorer"
                            >
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                        </td>
                        <td className="p-2.5 text-[#a39886] max-w-[140px] truncate" title={item.label}>
                          {item.label}
                        </td>
                        <td className="p-2.5">
                          {item.status === "pending" && (
                            <span className="text-[#746c60] text-[11px]">Pending</span>
                          )}
                          {item.status === "analyzing" && (
                            <span className="text-[#e8a54b] flex items-center gap-1 text-[11px] font-bold">
                              <Loader2 className="w-3 h-3 animate-spin" />
                              Analyzing...
                            </span>
                          )}
                          {item.status === "completed" && (
                            <span className="text-emerald-400 flex items-center gap-1 text-[11px]">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              Done
                            </span>
                          )}
                          {item.status === "failed" && (
                            <span
                              className="text-red-400 flex items-center gap-1 text-[11px]"
                              title={item.error}
                            >
                              <XCircle className="w-3.5 h-3.5" />
                              Failed
                            </span>
                          )}
                        </td>
                        <td className="p-2.5 text-center font-bold">
                          {typeof item.riskScore === "number" ? (
                            <span
                              className={`px-1.5 py-0.5 rounded text-[11px] ${
                                item.riskScore >= 70
                                  ? "bg-red-950 text-red-300"
                                  : item.riskScore >= 40
                                  ? "bg-amber-950 text-amber-300"
                                  : "bg-emerald-950 text-emerald-300"
                              }`}
                            >
                              {item.riskScore}
                            </span>
                          ) : (
                            <span className="text-[#746c60]">—</span>
                          )}
                        </td>
                        <td className="p-2.5 text-center">
                          {item.criticalCount && item.criticalCount > 0 ? (
                            <span className="text-red-400 font-bold">{item.criticalCount}</span>
                          ) : (
                            <span className="text-[#746c60]">0</span>
                          )}
                        </td>
                        <td className="p-2.5 text-center">
                          {item.highCount && item.highCount > 0 ? (
                            <span className="text-amber-400 font-bold">{item.highCount}</span>
                          ) : (
                            <span className="text-[#746c60]">0</span>
                          )}
                        </td>
                        <td className="p-2.5 text-right">
                          {item.report && item.rawBody ? (
                            <button
                              onClick={() => onInspectItem(item.report!, item.rawBody!, item.label)}
                              className="px-2 py-1 rounded bg-[#3a2c14] hover:bg-[#e8a54b] hover:text-[#12110e] text-[#e8a54b] text-[11px] font-bold flex items-center gap-1 ml-auto transition-colors"
                              title="Inspect full audit in Workbench"
                            >
                              <Eye className="w-3 h-3" />
                              <span>Inspect</span>
                            </button>
                          ) : (
                            <span className="text-[#746c60] text-[11px]">—</span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
