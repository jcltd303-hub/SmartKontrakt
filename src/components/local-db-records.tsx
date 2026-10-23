import { useState, useEffect } from "react";
import {
  listScans,
  getScan,
  getDbInfo,
  removeScan,
  saveComprehensiveScanFn,
  getDatabaseStatusFn,
  getScansStatsFn,
  getDatabaseSizeFn,
  type ScansListPayload,
} from "@/lib/scans.functions";
import { DB_FREE_TIER_CAP_BYTES, dbSizeLevel, dbSizePercentOfCap, formatDbBytes } from "@/lib/db-size";
import type { ScanSummary, StoredScan } from "@/lib/audit/persist.server";
import { SUPPORTED_CHAINS } from "@/lib/audit/address-fetcher";
import { balanceLabel, nativeSymbol } from "@/lib/audit/balance";
import { formatUsd } from "@/lib/audit/value";
import { SupabaseDbModal } from "./supabase-db-modal";
import {
  Database,
  Search,
  ExternalLink,
  Copy,
  Check,
  Trash2,
  Eye,
  Download,
  BookOpen,
  Layers,
  Activity,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Loader2,
  X,
  FileCode,
  ArrowRight,
  Filter,
} from "lucide-react";

interface LocalDbRecordsProps {
  onLoadInWorkbench: (scan: StoredScan) => void;
  onNavigateToRag: () => void;
  onNavigateToPocAudits?: () => void;
}

export function LocalDbRecords({ onLoadInWorkbench, onNavigateToRag, onNavigateToPocAudits }: LocalDbRecordsProps) {
  const [records, setRecords] = useState<ScanSummary[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [chainFilter, setChainFilter] = useState<string>("all");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  // Value-at-risk view: filter by whether anything is at stake, and sort by it.
  const [valueFilter, setValueFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<string>("recent");
  const [selectedRecord, setSelectedRecord] = useState<StoredScan | null>(null);
  const [loadingDetailId, setLoadingDetailId] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [indexingId, setIndexingId] = useState<string | null>(null);
  const [isDbModalOpen, setIsDbModalOpen] = useState<boolean>(false);
  // True totals from the server (the list below is paged; per-page sums
  // would undercount once the table grows past one page).
  const [stats, setStats] = useState<{ total: number; critical: number; high: number; ragIndexed: number } | null>(null);
  const [isLoadingMore, setIsLoadingMore] = useState<boolean>(false);
  // Surfaced query failure (#2): message + the identity of the database the
  // app is actually reading. Null = last load was fine (possibly genuinely
  // empty — that renders as an empty archive, not an error).
  const [recordsError, setRecordsError] = useState<{ message: string; db: ScansListPayload["db"] } | null>(null);
  // Database size guardrail (#3). Null = not loaded yet / fn unreachable;
  // totalBytes null inside = the read itself failed (fail soft).
  const [dbSize, setDbSize] = useState<Awaited<ReturnType<typeof getDatabaseSizeFn>> | null>(null);
  // Effective connection state, from getDatabaseStatusFn's dbInfo — the
  // same getDbConnectionState() resolution the queries use. The badge and
  // the header pill render THIS, never a hardcoded "Connected"/"Live":
  // "failed" (configured DB unreachable — no fallback exists anymore) and
  // "unconfigured" are first-class rendered states.
  const [dbStatus, setDbStatus] = useState<{ kind: "remote" | "failed" | "unconfigured" | "unknown"; label: string }>({
    kind: "unknown",
    label: "Checking database…",
  });
  // Partial-data warning (schema drift / degraded read): data is shown,
  // but the archive is older than this build and the banner says so.
  const [recordsWarning, setRecordsWarning] = useState<string | null>(null);
  // Configured identity for the genuinely-empty rendering (state remote,
  // zero rows): the empty archive names the database it is empty IN.
  const [dbIdentityLabel, setDbIdentityLabel] = useState<string | null>(null);

  const fetchRecords = async () => {
    setIsLoading(true);
    try {
      const data = await listScans({ data: { limit: 60, offset: 0 } });
      setRecords(data.summaries);
      // #2: a failed query surfaces as a banner (message + DB identity)
      // instead of the old silent empty list. Genuinely empty arrives with
      // error: null and renders as an empty archive. A partial read
      // (schema drift) arrives with data + a warning banner.
      setRecordsError(data.error ? { message: data.error, db: data.db } : null);
      setRecordsWarning(data.warning ?? null);
      if (data.db) {
        setDbIdentityLabel(`${data.db.user}@${data.db.host}:${data.db.port}/${data.db.database}`);
      }
      try {
        const s = await getScansStatsFn();
        if (s.error) {
          setRecordsError((prev) => prev ?? { message: s.error, db: s.db });
          // Stats failed independently of the list: leave stats null so
          // the cards render "—" (unknown), never the other query's zeros.
          setStats(null);
        } else {
          setStats(s.stats);
          if (s.warning) setRecordsWarning((prev) => prev ?? s.warning);
        }
      } catch {
        // stats stay null — cards render "—" while an error is showing,
        // otherwise totals fall back to loaded records
        setStats(null);
      }
      try {
        setDbSize(await getDatabaseSizeFn());
      } catch {
        setDbSize(null); // guardrail is best-effort; renders "size unavailable"
      }
      try {
        const status = await getDatabaseStatusFn();
        const info = status?.dbInfo;
        if (info?.state === "remote") {
          setDbStatus({ kind: "remote", label: "Supabase PostgreSQL (Live)" });
        } else if (info?.state === "failed") {
          setDbStatus({ kind: "failed", label: "Database connection FAILED" });
        } else if (info?.state === "unconfigured") {
          setDbStatus({ kind: "unconfigured", label: "No database configured" });
        } else if (info?.connected) {
          setDbStatus({ kind: "remote", label: "Supabase PostgreSQL (Live)" });
        }
      } catch {
        // status stays as-is; the records payloads carry their own state
      }
      try {
        const info = await getDbInfo();
        if (info) {
          if (info.user && info.host) {
            setDbIdentityLabel(`${info.user}@${info.host}:${info.port}/${info.database}`);
          }
          setDbStatus((prev) =>
            prev.kind !== "unknown"
              ? prev
              : info.state === "failed"
                ? { kind: "failed", label: "Database connection FAILED" }
                : info.state === "unconfigured"
                  ? { kind: "unconfigured", label: "No database configured" }
                  : { kind: "remote", label: "Supabase PostgreSQL (Live)" },
          );
        }
      } catch {
        // identity label stays null; the empty state renders generically
      }
    } catch (err) {
      // Transport-level failure: the server fn itself was unreachable.
      setRecordsError({ message: err instanceof Error ? err.message : String(err), db: null });
    } finally {
      setIsLoading(false);
    }
  };

  const fetchMore = async () => {
    if (isLoadingMore) return;
    setIsLoadingMore(true);
    try {
      const page = await listScans({ data: { limit: 60, offset: records.length } });
      if (page.error) {
        setRecordsError({ message: page.error, db: page.db });
        return;
      }
      if (page.warning) setRecordsWarning(page.warning);
      if (page.summaries.length > 0) {
        setRecords((prev) => {
          const seen = new Set(prev.map((r) => r.id));
          return [...prev, ...page.summaries.filter((r) => !seen.has(r.id))];
        });
      }
    } catch (err) {
      console.warn("[kiln] Failed to fetch more Supabase DB records:", err);
    } finally {
      setIsLoadingMore(false);
    }
  };

  useEffect(() => {
    fetchRecords();
  }, []);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleOpenDetail = async (id: string) => {
    setLoadingDetailId(id);
    try {
      const full = await getScan({ data: { id } });
      setSelectedRecord(full);
    } catch {
      setActionNotice("Could not load full audit record from Supabase DB.");
      setTimeout(() => setActionNotice(null), 3000);
    } finally {
      setLoadingDetailId(null);
    }
  };

  const handleDelete = async (id: string, label: string) => {
    if (!confirm(`Permanently remove audit record "${label}" from Supabase database?`)) return;
    const doomed = records.find((r) => r.id === id);
    try {
      await removeScan({ data: { id } });
      setRecords((prev) => prev.filter((r) => r.id !== id));
      if (doomed) {
        setStats((prev) =>
          prev
            ? {
                total: Math.max(0, prev.total - 1),
                critical: Math.max(0, prev.critical - doomed.criticalCount),
                high: Math.max(0, prev.high - doomed.highCount),
                ragIndexed: Math.max(0, prev.ragIndexed - (doomed.isRagIndexed ? 1 : 0)),
              }
            : prev,
        );
      }
      if (selectedRecord?.id === id) setSelectedRecord(null);
      setActionNotice("Record deleted from Supabase DB.");
      setTimeout(() => setActionNotice(null), 3000);
    } catch {
      setActionNotice("Failed to delete record.");
      setTimeout(() => setActionNotice(null), 3000);
    }
  };

  const handleIndexToRag = async (id: string) => {
    setIndexingId(id);
    try {
      const full = await getScan({ data: { id } });
      await saveComprehensiveScanFn({
        data: {
          id: full.id,
          label: full.label,
          report: full.report,
          body: full.body,
          targetAddress: full.targetAddress,
          chainId: full.chainId,
          proxyInfo: full.proxyInfo,
          probes: full.probes,
          aiReview: full.aiReview,
          triageStates: full.triageStates,
          certHash: full.certHash,
          sourceOrigin: full.sourceOrigin,
          indexToRag: true,
        },
      });
      setRecords((prev) =>
        prev.map((r) => (r.id === id ? { ...r, isRagIndexed: true } : r))
      );
      setActionNotice("Successfully indexed report into Local RAG Knowledgebase!");
      setTimeout(() => setActionNotice(null), 3500);
    } catch (err) {
      setActionNotice("RAG indexing failed: " + String(err));
      setTimeout(() => setActionNotice(null), 3500);
    } finally {
      setIndexingId(null);
    }
  };

  const handleExportAllRecords = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(records, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `kiln_local_db_audits_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Filtered records
  const filtered = records.filter((r) => {
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchLabel = r.label.toLowerCase().includes(q);
      const matchContract = (r.contractName ?? "").toLowerCase().includes(q);
      const matchAddr = (r.targetAddress ?? "").toLowerCase().includes(q);
      if (!matchLabel && !matchContract && !matchAddr) return false;
    }
    if (chainFilter !== "all" && r.chainId !== chainFilter) return false;
    if (riskFilter === "critical" && r.riskScore < 75) return false;
    if (riskFilter === "high" && (r.riskScore < 50 || r.riskScore >= 75)) return false;
    if (riskFilter === "medium" && (r.riskScore < 25 || r.riskScore >= 50)) return false;
    if (riskFilter === "low" && r.riskScore >= 25) return false;
    // Value-at-risk: a record with no valuation (null) is "unknown", not "zero".
    if (valueFilter === "funded" && !((r.valueUsd ?? 0) > 0)) return false;
    if (valueFilter === "zero" && r.valueUsd !== 0) return false;
    if (valueFilter === "unknown" && r.valueUsd !== null && r.valueUsd !== undefined) return false;
    return true;
  });

  // Value at risk across everything currently filtered (the whole loaded set,
  // not just the visible page), plus a sortable view.
  const valueAtRisk = filtered.reduce((acc, r) => acc + (r.valueUsd ?? 0), 0);
  const fundedCount = filtered.filter((r) => (r.valueUsd ?? 0) > 0).length;
  const visible = [...filtered].sort((a, b) => {
    if (sortBy === "value-desc") return (b.valueUsd ?? -1) - (a.valueUsd ?? -1);
    if (sortBy === "value-asc") return (a.valueUsd ?? Number.POSITIVE_INFINITY) - (b.valueUsd ?? Number.POSITIVE_INFINITY);
    if (sortBy === "risk-desc") return b.riskScore - a.riskScore;
    return 0; // "recent" — the server already returns newest first
  });

  // Aggregated Stats — true totals from the server, not per-page sums.
  // (With pagination, summing only the loaded page would undercount.)
  // When a query failed, the totals are UNKNOWN — the cards render "—",
  // never a fabricated 0. A bare 0 for a failed read was the original bug.
  const statsUnknown = recordsError !== null && stats === null;
  const totalAudits = stats?.total ?? records.length;
  const criticalFindings = stats?.critical ?? records.reduce((acc, r) => acc + r.criticalCount, 0);
  const highFindings = stats?.high ?? records.reduce((acc, r) => acc + r.highCount, 0);
  const ragIndexedCount = stats?.ragIndexed ?? records.filter((r) => r.isRagIndexed).length;
  const hasMore = !statsUnknown && records.length < totalAudits;

  return (
    <div className="flex flex-col gap-6 animate-fadeIn pb-12 font-sans">
      {/* Top Banner & Stats */}
      <div className="bg-[#1c1a16] border border-[#3a3428] rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-[#e8a54b]/5 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20" />

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-[#e8a54b]/10 border border-[#e8a54b]/30">
                <Database className="w-5 h-5 text-[#e8a54b]" />
              </div>
              <h2 className="text-xl font-bold font-mono tracking-tight text-[#f4efe6]">
                Supabase Audit Dossiers & Archive
              </h2>
              <span
                className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border ${
                  dbStatus.kind === "failed"
                    ? "bg-red-950/60 text-red-400 border-red-700/60"
                    : dbStatus.kind === "unconfigured"
                      ? "bg-amber-950/60 text-amber-400 border-amber-700/60"
                      : "bg-emerald-950/60 text-emerald-400 border-emerald-700/60"
                }`}
              >
                {dbStatus.label}
              </span>
            </div>
            <p className="text-xs text-[#a39886] mt-1.5 max-w-2xl leading-relaxed">
              Durable Supabase PostgreSQL database records preserving comprehensive smart contract audit reports, AST inventories,
              EIP-1967 proxy resolutions, on-chain view probes, and official verification hashes.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              onClick={() => setIsDbModalOpen(true)}
              className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-1.5 transition-colors ${
                dbStatus.kind === "remote"
                  ? "bg-emerald-950/60 hover:bg-emerald-900/60 border-emerald-700/60 text-emerald-400"
                  : dbStatus.kind === "failed"
                    ? "bg-red-950/60 hover:bg-red-900/60 border-red-700/60 text-red-400"
                    : "bg-[#26231c] hover:bg-[#3a3428] border-[#3a3428] text-[#e8a54b]"
              }`}
              title="Configure Supabase Database Connection & Credentials"
            >
              <Database className="w-3.5 h-3.5 text-[#e8a54b]" />
              <span>
                {dbStatus.kind === "remote"
                  ? "Supabase DB: Connected"
                  : dbStatus.kind === "failed"
                    ? "Supabase DB: Connection FAILED"
                    : dbStatus.kind === "unconfigured"
                      ? "Wire Supabase DB"
                      : "Supabase DB: …"}
              </span>
            </button>
            <button
              onClick={fetchRecords}
              className="px-3 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-xs font-mono text-[#f4efe6] flex items-center gap-1.5 transition-colors"
              title="Refresh database records"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-[#e8a54b] ${isLoading ? "animate-spin" : ""}`} />
              <span>Refresh</span>
            </button>
            <button
              onClick={handleExportAllRecords}
              className="px-3 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-xs font-mono text-[#f4efe6] flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-[#e8a54b]" />
              <span>Export Archive JSON</span>
            </button>
            {onNavigateToPocAudits && (
              <button
                onClick={onNavigateToPocAudits}
                className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-[#e8a54b] to-[#d97706] hover:brightness-110 text-[#12110e] text-xs font-bold font-mono tracking-wide flex items-center gap-1.5 shadow transition-all active:scale-95"
                title="Audit all recent Critical/High findings with Foundry PoC"
              >
                <ShieldAlert className="w-3.5 h-3.5 fill-current" />
                <span>PoC Audits ({criticalFindings + highFindings} Vulns)</span>
              </button>
            )}
          </div>
        </div>

        {/* Database Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5 pt-5 border-t border-[#3a3428]/60 font-mono text-xs">
          <div className="bg-[#12110e]/70 p-3 rounded-xl border border-[#3a3428]/40">
            <div className="text-[10px] text-[#746c60] uppercase tracking-wider">Total Audits Stored</div>
            <div className="text-lg font-bold text-[#e8a54b] mt-0.5">{statsUnknown ? "—" : totalAudits}</div>
          </div>
          <div className="bg-[#12110e]/70 p-3 rounded-xl border border-[#3a3428]/40">
            <div className="text-[10px] text-[#746c60] uppercase tracking-wider">Critical Vulns Logged</div>
            <div className="text-lg font-bold text-red-400 mt-0.5">{statsUnknown ? "—" : criticalFindings}</div>
          </div>
          <div className="bg-[#12110e]/70 p-3 rounded-xl border border-[#3a3428]/40">
            <div className="text-[10px] text-[#746c60] uppercase tracking-wider">High Vulns Logged</div>
            <div className="text-lg font-bold text-orange-400 mt-0.5">{statsUnknown ? "—" : highFindings}</div>
          </div>
          <button
            onClick={onNavigateToRag}
            className="bg-[#12110e]/70 hover:bg-[#12110e] p-3 rounded-xl border border-[#3a3428]/40 hover:border-[#e8a54b]/50 text-left transition-colors cursor-pointer group"
            title="Open RAG Knowledgebase"
          >
            <div className="text-[10px] text-[#746c60] uppercase tracking-wider flex items-center justify-between">
              <span>RAG KB Synced</span>
              <BookOpen className="w-3 h-3 text-[#e8a54b] group-hover:scale-110 transition-transform" />
            </div>
            <div className="text-lg font-bold text-emerald-400 mt-0.5">{statsUnknown ? "—" : `${ragIndexedCount} / ${totalAudits}`}</div>
          </button>
        </div>

        {/* Database size guardrail (#3): total vs the 500 MB free-tier cap,
            amber above 400 MB, red above 475 MB. Fail soft: an unreadable
            size renders "size unavailable", never an error state. */}
        <div className="mt-4 pt-3 border-t border-[#3a3428]/60 font-mono text-[11px] flex flex-wrap items-center gap-x-4 gap-y-1 relative z-10">
          <span className="text-[10px] text-[#746c60] uppercase tracking-wider">Database Size</span>
          {dbSize === null || dbSize.totalBytes === null ? (
            <span className="text-[#a39886]">size unavailable{dbSize?.error ? ` — ${dbSize.error}` : ""}</span>
          ) : (
            <>
              <span
                className={
                  dbSizeLevel(dbSize.totalBytes) === "critical"
                    ? "text-red-400 font-bold"
                    : dbSizeLevel(dbSize.totalBytes) === "warn"
                      ? "text-amber-400 font-bold"
                      : "text-[#a39886]"
                }
                title={dbSize.error ?? undefined}
              >
                {formatDbBytes(dbSize.totalBytes)} of {formatDbBytes(DB_FREE_TIER_CAP_BYTES)} free-tier cap ({dbSizePercentOfCap(dbSize.totalBytes)}%)
              </span>
              {dbSize.tables.slice(0, 5).map((t) => (
                <span key={t.name} className="text-[#746c60]">
                  {t.name} <span className="text-[#a39886]">{formatDbBytes(t.bytes)}</span>
                </span>
              ))}
            </>
          )}
        </div>
      </div>

      {recordsError && (
        <div className="p-3 bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono rounded-xl flex items-start gap-2 animate-fadeIn">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="min-w-0">
            <div className="font-bold">
              {recordsError.db?.state === "failed"
                ? "Configured database unreachable — no fallback is in use; the archive is NOT being read."
                : recordsError.db?.state === "unconfigured"
                  ? "No database configured — Records has no archive to read."
                  : "Records query failed — showing nothing rather than inventing an empty archive."}
            </div>
            <div className="mt-0.5 break-words">{recordsError.message}</div>
            {recordsError.db && recordsError.db.state === "failed" && (
              <div className="mt-0.5 text-red-400/90">
                Configured target: {recordsError.db.user}@{recordsError.db.host}:{recordsError.db.port}/{recordsError.db.database}
                {recordsError.db.error ? ` — ${recordsError.db.error}` : ""}
              </div>
            )}
            {recordsError.db && recordsError.db.state !== "failed" && !recordsError.db.error && (
              <div className="mt-0.5 text-red-400/90">
                Reading from {recordsError.db.user}@{recordsError.db.host}:{recordsError.db.port}/{recordsError.db.database} — if
                that is the wrong project, fix it in Supabase Config.
              </div>
            )}
            {recordsError.db?.state !== "failed" && recordsError.db?.error && (
              <div className="mt-0.5 text-red-400/90">{recordsError.db.error}</div>
            )}
          </div>
        </div>
      )}

      {recordsWarning && !recordsError && (
        <div className="p-3 bg-amber-950/70 border border-amber-800 text-amber-300 text-xs font-mono rounded-xl flex items-start gap-2 animate-fadeIn">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="min-w-0">
            <div className="font-bold">Partial archive data — read with a degraded schema.</div>
            <div className="mt-0.5 break-words">{recordsWarning}</div>
          </div>
        </div>
      )}

      {actionNotice && (
        <div className="p-3 bg-emerald-950/70 border border-emerald-800 text-emerald-300 text-xs font-mono rounded-xl animate-fadeIn">
          {actionNotice}
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 text-xs font-mono">
        <div className="relative flex-1">
          <Search className="w-3.5 h-3.5 text-[#a39886] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search records by name, address (0x...), or label"
            className="w-full bg-[#12110e] border border-[#3a3428] rounded-lg pl-9 pr-3 py-1.5 text-xs text-[#f4efe6] placeholder-[#746c60] focus:outline-none focus:border-[#e8a54b]"
          />
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1.5 bg-[#12110e] px-2.5 py-1 rounded-lg border border-[#3a3428]">
            <Filter className="w-3 h-3 text-[#a39886]" />
            <span className="text-[#a39886] text-[11px]">Chain:</span>
            <select
              value={chainFilter}
              onChange={(e) => setChainFilter(e.target.value)}
              className="bg-transparent text-[#e8a54b] focus:outline-none cursor-pointer text-xs"
            >
              <option value="all" className="bg-[#1c1a16] text-[#f4efe6]">All Chains</option>
              {SUPPORTED_CHAINS.map((c) => (
                <option key={c.id} value={c.id} className="bg-[#1c1a16] text-[#f4efe6]">
                  {c.name}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-1.5 bg-[#12110e] px-2.5 py-1 rounded-lg border border-[#3a3428]">
            <span className="text-[#a39886] text-[11px]">Risk Tier:</span>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="bg-transparent text-[#e8a54b] focus:outline-none cursor-pointer text-xs"
            >
              <option value="all" className="bg-[#1c1a16] text-[#f4efe6]">All Risk Scores</option>
              <option value="critical" className="bg-[#1c1a16] text-red-400">Critical (75-100)</option>
              <option value="high" className="bg-[#1c1a16] text-orange-400">High (50-74)</option>
              <option value="medium" className="bg-[#1c1a16] text-amber-300">Medium (25-49)</option>
              <option value="low" className="bg-[#1c1a16] text-emerald-400">Low (&lt;25)</option>
            </select>
          </div>

          {/* Value at risk: the triage axis that actually matters. */}
          <div className="flex items-center gap-1.5 bg-[#12110e] px-2.5 py-1 rounded-lg border border-[#3a3428]">
            <span className="text-[#a39886] text-[11px]">Value:</span>
            <select
              value={valueFilter}
              onChange={(e) => setValueFilter(e.target.value)}
              className="bg-transparent text-[#e8a54b] focus:outline-none cursor-pointer text-xs"
            >
              <option value="all" className="bg-[#1c1a16] text-[#f4efe6]">All</option>
              <option value="funded" className="bg-[#1c1a16] text-[#e8c07d]">Funded (&gt; $0)</option>
              <option value="zero" className="bg-[#1c1a16] text-red-400">Zero value</option>
              <option value="unknown" className="bg-[#1c1a16] text-[#a39886]">Not valued</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5 bg-[#12110e] px-2.5 py-1 rounded-lg border border-[#3a3428]">
            <span className="text-[#a39886] text-[11px]">Sort:</span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="bg-transparent text-[#e8a54b] focus:outline-none cursor-pointer text-xs"
            >
              <option value="recent" className="bg-[#1c1a16] text-[#f4efe6]">Newest</option>
              <option value="value-desc" className="bg-[#1c1a16] text-[#f4efe6]">Value (high to low)</option>
              <option value="value-asc" className="bg-[#1c1a16] text-[#f4efe6]">Value (low to high)</option>
              <option value="risk-desc" className="bg-[#1c1a16] text-[#f4efe6]">Risk score</option>
            </select>
          </div>
        </div>
      </div>

      {/* Value at risk across the current selection — the headline number. */}
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 px-4 py-3 mb-3 bg-[#1c1a16] border border-[#3a3428] rounded-xl font-mono">
        <div className="flex items-baseline gap-2">
          <span className="text-[10px] uppercase tracking-wider text-[#746c60]">Value at risk</span>
          <span className="text-lg font-bold text-[#e8c07d]">{formatUsd(valueAtRisk) ?? "$0.00"}</span>
        </div>
        <span className="text-[11px] text-[#a39886]">
          {fundedCount} funded / {filtered.length} shown
        </span>
        {valueFilter !== "all" && (
          <span className="text-[10px] text-[#746c60]">filtered by value</span>
        )}
      </div>

      {/* Records Table / List */}
      <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl overflow-hidden shadow-sm">
        {isLoading ? (
          <div className="p-12 text-center text-xs font-mono text-[#a39886] flex flex-col items-center justify-center gap-3">
            <Loader2 className="w-8 h-8 text-[#e8a54b] animate-spin" />
            <span>Loading records from database...</span>
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-12 text-center text-xs font-mono text-[#a39886] flex flex-col items-center justify-center gap-3">
            <Database className="w-8 h-8 text-[#746c60]" />
            {records.length === 0 &&
            stats?.total === 0 &&
            !recordsError &&
            !searchQuery.trim() &&
            chainFilter === "all" &&
            riskFilter === "all" &&
            valueFilter === "all" ? (
              <span>
                Archive is empty — 0 audits stored
                {dbIdentityLabel ? ` in ${dbIdentityLabel}` : " in the configured database"}. This is a real
                empty result from a connected database, not a connection failure.
              </span>
            ) : (
              <span>No audit records found matching your filters.</span>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-[#26231c] border-b border-[#3a3428] text-[#a39886] uppercase text-[10px] tracking-wider">
                <tr>
                  <th className="p-3">Target Contract</th>
                  <th className="p-3">Chain & Address</th>
                  <th className="p-3">Risk Score</th>
                  <th className="p-3">Value at Risk</th>
                  <th className="p-3">Findings Breakdown</th>
                  <th className="p-3">Dossier Features</th>
                  <th className="p-3">Date Saved</th>
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#3a3428]/60 text-[#f4efe6]">
                {visible.map((r) => {
                  const riskColor =
                    r.riskScore >= 75
                      ? "text-red-400 border-red-700/60 bg-red-950/40"
                      : r.riskScore >= 50
                      ? "text-orange-400 border-orange-700/60 bg-orange-950/40"
                      : r.riskScore >= 25
                      ? "text-amber-300 border-amber-700/60 bg-amber-950/40"
                      : "text-emerald-400 border-emerald-700/60 bg-emerald-950/40";

                  const chainObj = SUPPORTED_CHAINS.find((c) => c.id === r.chainId);
                  const explorerUrl = r.targetAddress && chainObj?.blockExplorer ? `${chainObj.blockExplorer}/address/${r.targetAddress}` : null;

                  return (
                    <tr key={r.id} className="hover:bg-[#26231c]/40 transition-colors">
                      {/* Contract Name & Label */}
                      <td className="p-3">
                        <div className="font-bold text-[#f4efe6] max-w-[200px] truncate" title={r.label}>
                          {r.contractName || r.label}
                        </div>
                        <div className="text-[10px] text-[#746c60] truncate max-w-[200px]">
                          {r.inputKind === "bytecode" ? "EVM Runtime Bytecode" : "Solidity Source"}
                        </div>
                      </td>

                      {/* Chain & Target Address */}
                      <td className="p-3">
                        <div className="flex items-center gap-1.5 text-[11px] text-[#e8a54b]">
                          <span>{chainObj?.name ?? r.chainId ?? "Ethereum"}</span>
                        </div>
                        {/* Native balance at analysis time (migration 0011). */}
                        {(() => {
                          const bal = balanceLabel(r.balanceWei, nativeSymbol(r.chainId));
                          return (
                            <div
                              className={`text-[10px] font-mono mt-0.5 ${bal === null ? "text-[#746c60]" : bal.startsWith("0 ") ? "text-red-400" : "text-[#e8c07d]"}`}
                              title="Native coin balance of the target at analysis time"
                            >
                              {bal ?? "balance n/a"}
                            </div>
                          );
                        })()}
                        {r.targetAddress ? (
                          <div className="flex items-center gap-1 text-[10px] text-[#a39886] mt-0.5">
                            <span className="truncate max-w-[110px]">{r.targetAddress}</span>
                            <button
                              onClick={() => copyToClipboard(r.targetAddress!, `addr-${r.id}`)}
                              className="text-[#746c60] hover:text-[#f4efe6]"
                              title="Copy Address"
                            >
                              {copiedKey === `addr-${r.id}` ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
                            </button>
                            {explorerUrl && (
                              <a
                                href={explorerUrl}
                                target="_blank"
                                rel="noreferrer"
                                className="text-[#746c60] hover:text-[#e8a54b]"
                                title="View on Block Explorer"
                              >
                                <ExternalLink className="w-2.5 h-2.5" />
                              </a>
                            )}
                          </div>
                        ) : (
                          <span className="text-[10px] text-[#746c60]">Source code upload</span>
                        )}
                      </td>

                      {/* Risk Score */}
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-bold border ${riskColor}`}>
                          {r.riskScore}/100
                        </span>
                      </td>

                      {/* Value at Risk — USD total, with the native balance beneath. */}
                      <td className="p-3">
                        {(() => {
                          const v = r.valueUsd ?? null;
                          return (
                            <>
                              <div
                                className={`text-xs font-bold font-mono ${v === null ? "text-[#746c60]" : v > 0 ? "text-[#e8c07d]" : "text-red-400"}`}
                                title="Total USD value of the target (native + ERC-20) at analysis time"
                              >
                                {v === null ? "—" : formatUsd(v)}
                              </div>
                              <div className="text-[10px] text-[#746c60] font-mono mt-0.5">
                                {balanceLabel(r.balanceWei, nativeSymbol(r.chainId)) ?? ""}
                              </div>
                            </>
                          );
                        })()}
                      </td>

                      {/* Findings Breakdown */}
                      <td className="p-3">
                        <div className="flex items-center gap-1 text-[10px]">
                          {r.criticalCount > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-red-950/80 text-red-400 font-bold border border-red-700/60">
                              {r.criticalCount}C
                            </span>
                          )}
                          {r.highCount > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-orange-950/80 text-orange-400 font-bold border border-orange-700/60">
                              {r.highCount}H
                            </span>
                          )}
                          {r.mediumCount > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-amber-950/80 text-amber-300 font-bold border border-amber-700/60">
                              {r.mediumCount}M
                            </span>
                          )}
                          {r.lowCount > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-blue-950/80 text-blue-300 font-bold border border-blue-700/60">
                              {r.lowCount}L
                            </span>
                          )}
                          {r.unparsed ? (
                            <span className="text-amber-400 flex items-center gap-1">
                              <AlertTriangle className="w-3 h-3" /> Unparsed
                            </span>
                          ) : (
                            r.criticalCount === 0 && r.highCount === 0 && r.mediumCount === 0 && (
                              <span className="text-emerald-400 flex items-center gap-1">
                                <CheckCircle2 className="w-3 h-3" /> Clean
                              </span>
                            )
                          )}
                        </div>
                      </td>

                      {/* Features Badges */}
                      <td className="p-3">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {r.hasProxy && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-purple-950/80 text-purple-300 border border-purple-700/60 flex items-center gap-1">
                              <Layers className="w-2.5 h-2.5" /> Proxy
                            </span>
                          )}
                          {r.probesCount && r.probesCount > 0 ? (
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-blue-950/80 text-blue-300 border border-blue-700/60 flex items-center gap-1">
                              <Activity className="w-2.5 h-2.5" /> {r.probesCount} Probes
                            </span>
                          ) : null}
                          {r.isRagIndexed ? (
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-950/80 text-emerald-300 border border-emerald-700/60 flex items-center gap-1">
                              <BookOpen className="w-2.5 h-2.5" /> RAG Synced
                            </span>
                          ) : (
                            <button
                              onClick={() => handleIndexToRag(r.id)}
                              disabled={indexingId === r.id}
                              className="px-1.5 py-0.5 rounded text-[10px] bg-[#26231c] hover:bg-[#3a3428] text-[#e8a54b] border border-[#3a3428] flex items-center gap-1 transition-colors"
                              title="Index into local RAG knowledgebase"
                            >
                              {indexingId === r.id ? <Loader2 className="w-2.5 h-2.5 animate-spin" /> : <BookOpen className="w-2.5 h-2.5" />}
                              <span>Index RAG</span>
                            </button>
                          )}
                        </div>
                      </td>

                      {/* Date */}
                      <td className="p-3 text-[10px] text-[#746c60] whitespace-nowrap">
                        {r.createdAt ? new Date(r.createdAt).toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" }) : "—"}
                      </td>

                      {/* Actions */}
                      <td className="p-3 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => handleOpenDetail(r.id)}
                            disabled={loadingDetailId === r.id}
                            className="px-2.5 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] text-[#f4efe6] text-xs flex items-center gap-1 transition-colors disabled:opacity-50"
                            title="View Full Dossier"
                          >
                            {loadingDetailId === r.id ? (
                              <Loader2 className="w-3 h-3 text-[#e8a54b] animate-spin" />
                            ) : (
                              <Eye className="w-3 h-3 text-[#e8a54b]" />
                            )}
                            <span>Dossier</span>
                          </button>
                          <button
                            onClick={async () => {
                              const full = await getScan({ data: { id: r.id } });
                              onLoadInWorkbench(full);
                            }}
                            className="px-2.5 py-1 rounded bg-[#e8a54b] hover:brightness-110 text-[#12110e] font-bold text-xs flex items-center gap-1 transition-all shadow"
                            title="Open in active workbench"
                          >
                            <ArrowRight className="w-3 h-3" />
                            <span>Workbench</span>
                          </button>
                          <button
                            onClick={() => handleDelete(r.id, r.label)}
                            className="p-1 rounded text-[#746c60] hover:text-red-400 hover:bg-red-950/30 transition-colors"
                            title="Delete"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {hasMore && !isLoading && (
          <div className="p-4 text-center border-t border-[#3a3428]/60">
            <div className="text-[11px] text-[#a39886] font-mono mb-2">
              Loaded {records.length} of {totalAudits} audits
            </div>
            <button
              onClick={fetchMore}
              disabled={isLoadingMore}
              className="px-4 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-xs font-mono text-[#f4efe6] flex items-center gap-1.5 mx-auto transition-colors disabled:opacity-50"
            >
              {isLoadingMore ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null}
              <span>{isLoadingMore ? "Loading…" : "Load more (next 60)"}</span>
            </button>
          </div>
        )}
      </div>

      {/* Comprehensive Record Modal Dossier */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="bg-[#1c1a16] border border-[#3a3428] rounded-2xl max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden font-mono text-xs">
            {/* Modal Header */}
            <div className="p-4 sm:p-5 border-b border-[#3a3428] flex items-center justify-between bg-[#26231c]/60">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-[#e8a54b]" />
                <div>
                  <h3 className="font-bold text-sm text-[#f4efe6] truncate max-w-lg">
                    {selectedRecord.label}
                  </h3>
                  <div className="text-[11px] text-[#a39886]">
                    Audit Record ID: {selectedRecord.id}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => onLoadInWorkbench(selectedRecord)}
                  className="px-3 py-1.5 rounded bg-[#e8a54b] text-[#12110e] font-bold text-xs flex items-center gap-1.5 shadow"
                >
                  <ArrowRight className="w-3.5 h-3.5" />
                  <span>Open in Workbench</span>
                </button>
                <button
                  onClick={() => setSelectedRecord(null)}
                  className="p-1.5 rounded-lg text-[#a39886] hover:text-[#f4efe6] hover:bg-[#3a3428]"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Modal Content Scroll */}
            <div className="p-5 overflow-y-auto flex flex-col gap-5 flex-1 divide-y divide-[#3a3428]/50">
              {/* Executive Metrics Overview */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="bg-[#12110e] p-3 rounded-lg border border-[#3a3428]">
                  <div className="text-[10px] text-[#746c60] uppercase">Risk Score</div>
                  <div className="text-xl font-bold text-[#e8a54b] mt-1">{selectedRecord.riskScore}/100</div>
                </div>
                <div className="bg-[#12110e] p-3 rounded-lg border border-[#3a3428]">
                  <div className="text-[10px] text-[#746c60] uppercase">Findings</div>
                  <div className="text-xl font-bold text-red-400 mt-1">{selectedRecord.report.findings.length} issues</div>
                </div>
                <div className="bg-[#12110e] p-3 rounded-lg border border-[#3a3428]">
                  <div className="text-[10px] text-[#746c60] uppercase">Target Address</div>
                  <div className="text-xs font-bold text-[#f4efe6] mt-1 truncate" title={selectedRecord.targetAddress ?? "None"}>
                    {selectedRecord.targetAddress ?? "Source Code"}
                  </div>
                </div>
                <div className="bg-[#12110e] p-3 rounded-lg border border-[#3a3428]">
                  <div className="text-[10px] text-[#746c60] uppercase">Chain Network</div>
                  <div className="text-xs font-bold text-[#e8a54b] mt-1">{selectedRecord.chainId ?? "ethereum"}</div>
                </div>
              </div>

              {/* Proxy Architecture if detected */}
              {selectedRecord.proxyInfo?.isProxy && (
                <div className="pt-4 flex flex-col gap-2">
                  <span className="font-bold text-purple-300 flex items-center gap-1.5 text-xs">
                    <Layers className="w-3.5 h-3.5" />
                    {selectedRecord.proxyInfo.proxyType} Upgradeable Proxy Architecture
                  </span>
                  <div className="bg-purple-950/20 border border-purple-800/60 p-3 rounded-lg text-purple-200">
                    <div>Implementation Address: {selectedRecord.proxyInfo.implementationAddress}</div>
                    {selectedRecord.proxyInfo.adminAddress && <div>Admin Controller: {selectedRecord.proxyInfo.adminAddress}</div>}
                  </div>
                </div>
              )}

              {/* On-Chain View Probes */}
              {selectedRecord.probes && selectedRecord.probes.length > 0 && (
                <div className="pt-4 flex flex-col gap-2">
                  <span className="font-bold text-blue-300 flex items-center gap-1.5 text-xs">
                    <Activity className="w-3.5 h-3.5" />
                    On-Chain Interface Probes ({selectedRecord.probes.length})
                  </span>
                  <div className="border border-[#3a3428] rounded-lg overflow-x-auto max-h-48">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-[#26231c] text-[#a39886]">
                        <tr>
                          <th className="p-2">Selector</th>
                          <th className="p-2">Name</th>
                          <th className="p-2">Status</th>
                          <th className="p-2">Decoded Value</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#3a3428] text-[#f4efe6]">
                        {selectedRecord.probes.map((pr, i) => (
                          <tr key={i}>
                            <td className="p-2 text-[#e8a54b]">{pr.selector}</td>
                            <td className="p-2 font-bold">{pr.name}</td>
                            <td className="p-2">{pr.success ? "Success" : "Reverted"}</td>
                            <td className="p-2 text-blue-300">{pr.decodedString || pr.decodedNumber || pr.decodedAddress || "0x"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Findings Summary */}
              <div className="pt-4 flex flex-col gap-2">
                <span className="font-bold text-[#e8a54b] flex items-center gap-1.5 text-xs">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  Identified Vulnerabilities & Warnings
                </span>
                <div className="flex flex-col gap-2">
                  {selectedRecord.report.findings.map((f, i) => (
                    <div key={i} className="p-3 bg-[#12110e] rounded-lg border border-[#3a3428] flex flex-col gap-1">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-[#f4efe6]">
                          [{f.severity.toUpperCase()}] {f.title}
                        </span>
                        <span className="text-[10px] text-[#746c60]">{f.detector}</span>
                      </div>
                      <p className="text-[#a39886] text-[11px] leading-relaxed">{f.summary}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Source/Payload Excerpt */}
              <div className="pt-4 flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-[#a39886] text-xs">Contract Source / Payload</span>
                  <button
                    onClick={() => copyToClipboard(selectedRecord.body, "modal-body")}
                    className="text-[#e8a54b] hover:underline flex items-center gap-1 text-[11px]"
                  >
                    {copiedKey === "modal-body" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>Copy Code</span>
                  </button>
                </div>
                <div className="p-3 bg-[#12110e] rounded-lg border border-[#3a3428] max-h-48 overflow-y-auto text-[11px] text-[#a39886]">
                  <pre>{selectedRecord.body.slice(0, 4000)}</pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Supabase Database Connection Modal */}
      <SupabaseDbModal
        isOpen={isDbModalOpen}
        onClose={() => setIsDbModalOpen(false)}
        onDatabaseChanged={fetchRecords}
      />
    </div>
  );
}
