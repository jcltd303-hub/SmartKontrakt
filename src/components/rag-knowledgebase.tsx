import { useState, useEffect } from "react";
import {
  queryRagKnowledgebaseFn,
  listRagChunksFn,
  deleteRagChunkFn,
} from "@/lib/scans.functions";
import type { RagChunk } from "@/lib/audit/rag.server";
import {
  Search,
  BookOpen,
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  Check,
  Copy,
  Trash2,
  Download,
  Terminal,
  Layers,
  ChevronDown,
  ChevronRight,
  Tag,
  Loader2,
  RefreshCw,
  ArrowRight,
} from "lucide-react";

interface RagKnowledgebaseProps {
  onLoadContractInWorkbench?: (body: string, label: string) => void;
  activeScanPayload?: {
    label: string;
    body: string;
  } | null;
}

const SUGGESTED_QUERIES = [
  "Reentrancy with external ETH transfer (The DAO pattern)",
  "Unchecked ERC-20 transfer return value (USDT safeTransfer)",
  "Upgradeable proxy storage collision EIP-1967",
  "Read-only reentrancy in AMM liquidity pool oracles",
  "ERC-4626 first depositor share inflation attack",
  "Missing access control on critical admin initializers",
  "Precision loss and integer division before multiplication",
];

const CATEGORY_TABS: { id: string; label: string; icon: typeof BookOpen }[] = [
  { id: "all", label: "All Knowledge", icon: BookOpen },
  { id: "vulnerability", label: "Vulnerabilities", icon: ShieldAlert },
  { id: "remediation", label: "Remediation Patterns", icon: ShieldCheck },
  { id: "threat_model", label: "Threat Models", icon: Sparkles },
  { id: "foundry_poc", label: "Foundry PoCs", icon: Terminal },
  { id: "contract_profile", label: "Protocol Profiles", icon: Layers },
];

export function RagKnowledgebase({ onLoadContractInWorkbench }: RagKnowledgebaseProps) {
  const [query, setQuery] = useState<string>("");
  const [activeCategory, setActiveCategory] = useState<string>("all");
  const [chunks, setChunks] = useState<RagChunk[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [expandedChunkId, setExpandedChunkId] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Load initial chunks or search
  const performSearch = async (searchQuery: string, category: string) => {
    setIsLoading(true);
    try {
      if (searchQuery.trim()) {
        const results = await queryRagKnowledgebaseFn({
          data: {
            query: searchQuery.trim(),
            category: category === "all" ? undefined : category,
            limit: 40,
          },
        });
        setChunks(results);
      } else {
        const results = await listRagChunksFn({ data: { limit: 60 } });
        const filtered = category === "all" ? results : results.filter((c) => c.category === category);
        setChunks(filtered);
      }
    } catch (err) {
      console.warn("[Kiln-RAG] Query error:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    performSearch(query, activeCategory);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeCategory]);

  const handleSearchSubmit = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    performSearch(query, activeCategory);
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleDeleteChunk = async (id: string) => {
    if (!confirm("Remove this entry from the local RAG knowledgebase?")) return;
    try {
      await deleteRagChunkFn({ data: { id } });
      setChunks((prev) => prev.filter((c) => c.id !== id));
      setActionMessage("Entry deleted from local knowledgebase.");
      setTimeout(() => setActionMessage(null), 3000);
    } catch {
      setActionMessage("Failed to delete entry.");
      setTimeout(() => setActionMessage(null), 3000);
    }
  };

  const handleExportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(chunks, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `kiln_rag_knowledgebase_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Metrics
  const totalChunks = chunks.length;
  const vulnCount = chunks.filter((c) => c.category === "vulnerability").length;
  const remCount = chunks.filter((c) => c.category === "remediation").length;
  const pocCount = chunks.filter((c) => c.category === "foundry_poc").length;
  const threatCount = chunks.filter((c) => c.category === "threat_model").length;

  return (
    <div className="flex flex-col gap-6 animate-fadeIn pb-12 font-sans">
      {/* Top Banner & Stats */}
      <div className="bg-[#1c1a16] border border-[#3a3428] rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-[#e8a54b]/5 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20" />
        
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-[#e8a54b]/10 border border-[#e8a54b]/30">
                <BookOpen className="w-5 h-5 text-[#e8a54b]" />
              </div>
              <h2 className="text-xl font-bold font-mono tracking-tight text-[#f4efe6]">
                Local RAG Knowledgebase
              </h2>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-700/60">
                Semantic Vectors + BM25 Local DB
              </span>
            </div>
            <p className="text-xs text-[#a39886] mt-1.5 max-w-2xl leading-relaxed">
              Retrieval-Augmented Generation repository storing comprehensive audit dossiers, vulnerability patterns,
              exploit vectors, Foundry PoC tests, and verified Solidity remediation patches.
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => performSearch(query, activeCategory)}
              className="px-3 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-xs font-mono text-[#f4efe6] flex items-center gap-1.5 transition-colors"
              title="Refresh Knowledge Index"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-[#e8a54b] ${isLoading ? "animate-spin" : ""}`} />
              <span>Refresh</span>
            </button>
            <button
              onClick={handleExportJson}
              className="px-3 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-xs font-mono text-[#f4efe6] flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-[#e8a54b]" />
              <span>Export JSON</span>
            </button>
          </div>
        </div>

        {/* Knowledge Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mt-5 pt-5 border-t border-[#3a3428]/60 font-mono text-xs">
          <div className="bg-[#12110e]/70 p-3 rounded-xl border border-[#3a3428]/40">
            <div className="text-[10px] text-[#746c60] uppercase tracking-wider">Total Indexed</div>
            <div className="text-lg font-bold text-[#e8a54b] mt-0.5">{totalChunks}</div>
          </div>
          <div className="bg-[#12110e]/70 p-3 rounded-xl border border-[#3a3428]/40">
            <div className="text-[10px] text-[#746c60] uppercase tracking-wider">Vulnerabilities</div>
            <div className="text-lg font-bold text-red-400 mt-0.5">{vulnCount}</div>
          </div>
          <div className="bg-[#12110e]/70 p-3 rounded-xl border border-[#3a3428]/40">
            <div className="text-[10px] text-[#746c60] uppercase tracking-wider">Remediations</div>
            <div className="text-lg font-bold text-emerald-400 mt-0.5">{remCount}</div>
          </div>
          <div className="bg-[#12110e]/70 p-3 rounded-xl border border-[#3a3428]/40">
            <div className="text-[10px] text-[#746c60] uppercase tracking-wider">Foundry PoCs</div>
            <div className="text-lg font-bold text-amber-300 mt-0.5">{pocCount}</div>
          </div>
          <div className="bg-[#12110e]/70 p-3 rounded-xl border border-[#3a3428]/40 col-span-2 sm:col-span-1">
            <div className="text-[10px] text-[#746c60] uppercase tracking-wider">Threat Models</div>
            <div className="text-lg font-bold text-purple-300 mt-0.5">{threatCount}</div>
          </div>
        </div>
      </div>

      {actionMessage && (
        <div className="p-3 bg-emerald-950/70 border border-emerald-800 text-emerald-300 text-xs font-mono rounded-xl animate-fadeIn">
          {actionMessage}
        </div>
      )}

      {/* Search Bar & Query Input */}
      <div className="bg-[#1c1a16] border border-[#3a3428] rounded-2xl p-5 shadow-lg flex flex-col gap-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-[#a39886] absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Ask RAG knowledgebase (e.g. 'reentrancy in withdraw', 'USDT safeTransfer', 'storage collision')"
              className="w-full bg-[#12110e] border border-[#3a3428] rounded-xl pl-10 pr-4 py-2.5 text-xs font-mono text-[#f4efe6] placeholder-[#746c60] focus:outline-none focus:border-[#e8a54b] shadow-inner"
            />
          </div>
          <button
            type="submit"
            disabled={isLoading}
            className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-[#e8a54b] to-[#d97706] hover:brightness-110 text-[#12110e] font-bold text-xs font-mono tracking-wide flex items-center justify-center gap-2 shadow-md shadow-[#e8a54b]/20 transition-all shrink-0 active:scale-95 disabled:opacity-50"
          >
            {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4 fill-current" />}
            <span>Semantic Search</span>
          </button>
        </form>

        {/* Suggested Queries Chips */}
        <div className="flex items-center gap-1.5 flex-wrap pt-1 font-mono text-[11px]">
          <span className="text-[#746c60] text-[10px] uppercase font-bold tracking-wider mr-1">Quick Prompts:</span>
          {SUGGESTED_QUERIES.map((sq, i) => (
            <button
              key={i}
              onClick={() => {
                setQuery(sq);
                performSearch(sq, activeCategory);
              }}
              className="px-2.5 py-1 rounded-md bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#a39886] hover:text-[#f4efe6] transition-colors truncate max-w-[280px]"
              title={sq}
            >
              {sq}
            </button>
          ))}
        </div>
      </div>

      {/* Category Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1 font-mono text-xs border-b border-[#3a3428]/60">
        {CATEGORY_TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeCategory === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveCategory(tab.id)}
              className={`px-3.5 py-2 rounded-t-lg font-medium transition-all flex items-center gap-2 border-b-2 whitespace-nowrap ${
                isActive
                  ? "border-[#e8a54b] text-[#e8a54b] bg-[#1c1a16] font-bold"
                  : "border-transparent text-[#a39886] hover:text-[#f4efe6] hover:bg-[#1c1a16]/40"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Results List */}
      <div className="flex flex-col gap-4">
        {isLoading ? (
          <div className="p-12 text-center text-xs font-mono text-[#a39886] flex flex-col items-center justify-center gap-3">
            <Loader2 className="w-8 h-8 text-[#e8a54b] animate-spin" />
            <span>Scanning local RAG knowledge vectors & full-text index...</span>
          </div>
        ) : chunks.length === 0 ? (
          <div className="bg-[#1c1a16] border border-[#3a3428] rounded-2xl p-12 text-center flex flex-col items-center gap-3">
            <BookOpen className="w-10 h-10 text-[#746c60]" />
            <h3 className="text-sm font-bold font-mono text-[#f4efe6]">No Matching Knowledge Chunks</h3>
            <p className="text-xs text-[#a39886] max-w-md">
              No articles matched your query. Try broadening your terms or run an audit in the Workbench and click
              "Save to Local DB" to auto-index new security knowledge.
            </p>
          </div>
        ) : (
          chunks.map((chunk) => {
            const isExpanded = expandedChunkId === chunk.id;
            const score = chunk.relevanceScore ?? 100;
            const hasRemediation = Boolean(chunk.metadata?.remediationSolidity);
            const hasPoc = Boolean(chunk.metadata?.exploitSolidity || chunk.metadata?.foundryTestCode);

            return (
              <div
                key={chunk.id}
                className="bg-[#1c1a16] border border-[#3a3428] hover:border-[#e8a54b]/50 rounded-xl p-5 shadow-sm transition-all duration-150 flex flex-col gap-3"
              >
                {/* Header row */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    {/* Relevance Badge */}
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                        score >= 80
                          ? "bg-emerald-950/80 text-emerald-300 border-emerald-700/60"
                          : score >= 50
                          ? "bg-[#e8a54b]/20 text-[#e8a54b] border-[#e8a54b]/40"
                          : "bg-[#26231c] text-[#a39886] border-[#3a3428]"
                      }`}
                    >
                      {score}% MATCH
                    </span>

                    {/* Category Badge */}
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-[#26231c] text-[#a39886] border border-[#3a3428]">
                      {chunk.category.replace("_", " ")}
                    </span>

                    {/* Severity Badge */}
                    {chunk.severity && chunk.severity !== "general" && chunk.severity !== "architecture" && (
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                          chunk.severity === "critical"
                            ? "bg-red-950/80 text-red-400 border-red-700/60"
                            : chunk.severity === "high"
                            ? "bg-orange-950/80 text-orange-400 border-orange-700/60"
                            : chunk.severity === "medium"
                            ? "bg-amber-950/80 text-amber-300 border-amber-700/60"
                            : "bg-blue-950/80 text-blue-300 border-blue-700/60"
                        }`}
                      >
                        {chunk.severity}
                      </span>
                    )}

                    {chunk.swc && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-mono text-[#e8a54b] bg-[#e8a54b]/10 border border-[#e8a54b]/20">
                        {chunk.swc}
                      </span>
                    )}

                    {chunk.detector && (
                      <span className="text-[11px] font-mono text-[#746c60]">
                        #{chunk.detector}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2 self-end sm:self-auto">
                    {chunk.contractName && (
                      <span className="text-xs font-mono text-[#a39886] truncate max-w-[200px]">
                        {chunk.contractName}
                      </span>
                    )}
                    <button
                      onClick={() => setExpandedChunkId(isExpanded ? null : chunk.id)}
                      className="px-2.5 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] text-xs font-mono text-[#f4efe6] flex items-center gap-1 transition-colors"
                    >
                      <span>{isExpanded ? "Collapse" : "Deep Dive"}</span>
                      {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                    </button>
                    <button
                      onClick={() => handleDeleteChunk(chunk.id)}
                      className="p-1 rounded text-[#746c60] hover:text-red-400 hover:bg-red-950/30 transition-colors"
                      title="Remove chunk"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* Title */}
                <h3 className="text-sm font-bold font-mono text-[#f4efe6] leading-snug">
                  {chunk.title}
                </h3>

                {/* Excerpt / Highlight */}
                <div className="text-xs text-[#c9bfaf] font-mono leading-relaxed bg-[#12110e]/70 p-3 rounded-lg border border-[#3a3428]/50">
                  {chunk.highlightSnippet || chunk.content.slice(0, 220) + "..."}
                </div>

                {/* Deep Dive details when expanded */}
                {isExpanded && (
                  <div className="mt-2 pt-3 border-t border-[#3a3428] flex flex-col gap-4 animate-fadeIn font-mono text-xs">
                    {/* Full content body */}
                    <div className="whitespace-pre-wrap text-[#f4efe6] leading-relaxed bg-[#12110e] p-4 rounded-lg border border-[#3a3428] overflow-x-auto max-h-96 overflow-y-auto">
                      {chunk.content}
                    </div>

                    {/* Remediation code block if available */}
                    {hasRemediation && (
                      <div className="flex flex-col gap-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-emerald-400 font-bold flex items-center gap-1.5 text-xs">
                            <ShieldCheck className="w-3.5 h-3.5" />
                            Verified Solidity Remediation Pattern
                          </span>
                          <button
                            onClick={() => copyToClipboard(chunk.metadata.remediationSolidity!, `rem-${chunk.id}`)}
                            className="text-[#a39886] hover:text-[#f4efe6] flex items-center gap-1 text-[11px]"
                          >
                            {copiedKey === `rem-${chunk.id}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                            <span>Copy Fix</span>
                          </button>
                        </div>
                        <div className="p-3.5 bg-[#12110e] rounded-lg border border-emerald-950 text-emerald-300 overflow-x-auto">
                          <pre>{chunk.metadata.remediationSolidity}</pre>
                        </div>
                      </div>
                    )}

                    {/* Exploit PoC test if available */}
                    {hasPoc && (
                      <div className="flex flex-col gap-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-amber-300 font-bold flex items-center gap-1.5 text-xs">
                            <Terminal className="w-3.5 h-3.5" />
                            Executable Exploit PoC / Foundry Test
                          </span>
                          <button
                            onClick={() =>
                              copyToClipboard(
                                (chunk.metadata.exploitSolidity || chunk.metadata.foundryTestCode)!,
                                `poc-${chunk.id}`
                              )
                            }
                            className="text-[#a39886] hover:text-[#f4efe6] flex items-center gap-1 text-[11px]"
                          >
                            {copiedKey === `poc-${chunk.id}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                            <span>Copy PoC</span>
                          </button>
                        </div>
                        <div className="p-3.5 bg-[#12110e] rounded-lg border border-amber-950 text-amber-200 overflow-x-auto max-h-72">
                          <pre>{chunk.metadata.exploitSolidity || chunk.metadata.foundryTestCode}</pre>
                        </div>
                      </div>
                    )}

                    {/* Keywords tag pills */}
                    {chunk.keywords && chunk.keywords.length > 0 && (
                      <div className="flex items-center gap-1.5 flex-wrap pt-1 text-[10px] text-[#746c60]">
                        <Tag className="w-3 h-3" />
                        <span>Indexed Keywords:</span>
                        {chunk.keywords.map((kw, ki) => (
                          <span key={ki} className="px-1.5 py-0.5 rounded bg-[#26231c] text-[#a39886] border border-[#3a3428]">
                            {kw}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Action to test in Workbench */}
                    {onLoadContractInWorkbench && (chunk.metadata?.remediationSolidity || chunk.metadata?.exploitSolidity) && (
                      <div className="pt-2 border-t border-[#3a3428] flex justify-end">
                        <button
                          onClick={() => {
                            const code = chunk.metadata.remediationSolidity || chunk.metadata.exploitSolidity || "";
                            onLoadContractInWorkbench(code, `RAG: ${chunk.title}`);
                          }}
                          className="px-3 py-1.5 rounded bg-[#e8a54b] text-[#12110e] font-bold text-xs flex items-center gap-1.5 shadow hover:brightness-110"
                        >
                          <ArrowRight className="w-3.5 h-3.5" />
                          <span>Load Snippet in Workbench</span>
                        </button>
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
