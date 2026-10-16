import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import {
  parseAddressList,
  countValidAddresses,
  analyzeAddress,
  SUPPORTED_CHAINS,
  type BatchItem,
} from "@/lib/audit/address-fetcher";
import { detectProxyArchitecture } from "@/lib/audit/proxy-resolver";
import { probeContractInterfaces } from "@/lib/audit/simulator";
import {
  getStoredSupabaseConfig,
  saveStoredSupabaseConfig,
  testSupabaseConnection,
  createSupabaseBatchWriter,
  toSupabaseBatchRow,
  type SupabaseBatchRow,
  loadBatchFromSupabase,
  type SupabaseConfig,
} from "@/lib/supabase";
import { AsyncBatchWriter, ByteLruCache } from "@/lib/audit/batch-writer";
import { withRetry } from "@/lib/audit/rate-limit";
import { runSecondPassFn } from "@/lib/audit/ai.functions";
import { BatchQueue, retargetBatchQueue } from "@/lib/audit/batch-queue";
import { initializeBatchQueue, saveBatchCheckpoint } from "@/lib/audit/batch-checkpoint";
import type { Report } from "@/lib/audit/types";
import { saveBatchComprehensiveScansFn, listScans } from "@/lib/scans.functions";
import type { ComprehensiveRecordInput } from "@/lib/audit/persist.server";
import { SupabaseDbModal } from "./supabase-db-modal";
import { PipelineWorkerStatus } from "./pipeline-worker-status";
import {
  Play,
  Pause,
  RotateCcw,
  Upload,
  Download,
  Database,
  Server,
  Search,
  ExternalLink,
  Copy,
  Check,
  CheckCircle2,
  XCircle,
  X,
  AlertTriangle,
  Loader2,
  FileText,
  Sliders,
  RefreshCw,
  Eye,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Zap,
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
  const [aiSecondPass, setAiSecondPass] = useState<boolean>(false);
  const [fileMeta, setFileMeta] = useState<{ name: string; count: number; sizeKb: number } | null>(null);

  // Pagination state for handling 50,000+ items without DOM bloat
  const [pageSize, setPageSize] = useState<number>(50);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [jumpPageInput, setJumpPageInput] = useState<string>("");

  // Inspecting state and on-demand LRU cache (capped at 50 to avoid GBs of heap)
  const [inspectingAddr, setInspectingAddr] = useState<string | null>(null);
  const reportCacheRef = useRef(new ByteLruCache<{ report: Report; rawBody: string }>(50, 16_000_000));
  const localWriterRef = useRef<AsyncBatchWriter<ComprehensiveRecordInput> | null>(null);
  const remoteWriterRef = useRef<AsyncBatchWriter<SupabaseBatchRow> | null>(null);
  const pendingIndexesRef = useRef(new Map<string, number>());
  const pendingRemoteIndexesRef = useRef(new Map<string, number>());
  const remoteReplayRef = useRef<Promise<void> | null>(null);
  const mountedRef = useRef(true);
  const runnerActiveRef = useRef(false);
  const repaintTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const dirtyCheckpointRef = useRef(new Map<number, BatchItem>());
  const checkpointChainRef = useRef<Promise<void>>(Promise.resolve());
  const checkpointPendingRef = useRef(0);
  const checkpointReadyRef = useRef<Promise<void>>(Promise.resolve());
  const [queueRevision, setQueueRevision] = useState(0);
  const [checkpointError, setCheckpointError] = useState<string | null>(null);
  const [dbSyncStats, setDbSyncStats] = useState<{
    totalFlushed: number;
    pendingCount: number;
    isFlushing: boolean;
    lastError: string | null;
  }>({
    totalFlushed: 0,
    pendingCount: 0,
    isFlushing: false,
    lastError: null,
  });

  // Queue state (lightweight items, no duplicate source/AST trees in memory)
  const [queueStore] = useState(() => new BatchQueue(parseAddressList(SAMPLE_BATCH_INPUT, "ethereum")));
  const queue = queueStore.items;


  // Runner state
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [isPausing, setIsPausing] = useState<boolean>(false);
  const [currentIndex, setCurrentIndex] = useState<number>(-1);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [filterQuery, setFilterQuery] = useState<string>("");

  // Supabase state
  const [supabaseCfg, setSupabaseCfg] = useState<SupabaseConfig>(getStoredSupabaseConfig());
  const savedSupabaseCfgRef = useRef(supabaseCfg);
  const [isSupabaseModalOpen, setIsSupabaseModalOpen] = useState<boolean>(false);
  const [isDbWiringModalOpen, setIsDbWiringModalOpen] = useState<boolean>(false);
  const [supabaseStatusMsg, setSupabaseStatusMsg] = useState<{ ok: boolean; msg: string } | null>(null);
  const [isTestingSupabase, setIsTestingSupabase] = useState<boolean>(false);
  const [actionNotice, setActionNotice] = useState<{ ok: boolean; msg: string } | null>(null);
  const [isResumingSupabase, setIsResumingSupabase] = useState<boolean>(false);

  const showNotice = useCallback((msg: string, ok = true) => {
    setActionNotice({ ok, msg });
    setTimeout(() => {
      if (mountedRef.current) setActionNotice(null);
    }, 4500);
  }, []);

  const isRunningRef = useRef<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const checkpoint = useCallback((updates: [number, BatchItem][], replace = false) => {
    checkpointPendingRef.current++;
    checkpointChainRef.current = checkpointChainRef.current.catch(() => undefined)
      .then(async () => {
        await saveBatchCheckpoint(updates, replace);
        if (replace) { try { localStorage.removeItem("kiln_active_batch_queue"); } catch { /* IndexedDB is authoritative. */ } }
      }).catch((err: unknown) => {
        if (mountedRef.current) setCheckpointError(err instanceof Error ? err.message : String(err));
      }).finally(() => { checkpointPendingRef.current--; });
  }, []);

  const repaintQueue = useCallback(() => {
    if (repaintTimerRef.current) clearTimeout(repaintTimerRef.current);
    repaintTimerRef.current = null;
    const updates = Array.from(dirtyCheckpointRef.current.entries());
    dirtyCheckpointRef.current.clear();
    if (updates.length) checkpoint(updates);
    if (mountedRef.current) setQueueRevision((v) => v + 1);
  }, [checkpoint]);

  const updateQueueItem = useCallback((index: number, patch: Partial<BatchItem>) => {
    queueStore.update(index, patch);
    const item = queueStore.items[index];
    if (item) dirtyCheckpointRef.current.set(index, item);
    if (!repaintTimerRef.current) repaintTimerRef.current = setTimeout(repaintQueue, 200);
  }, [queueStore, repaintQueue]);

  const setQueue = useCallback((next: BatchItem[] | ((previous: BatchItem[]) => BatchItem[])) => {
    if (runnerActiveRef.current) {
      showNotice("Pipeline is still running — pause it before loading a new batch.", false);
      return false;
    }
    // No pending-writes block: the AsyncBatchWriter buffer is independent of
    // the UI queue, so replacing the queue never drops buffered records — the
    // writer keeps flushing them and the scanId guard in its write callback
    // skips stale persisted markings. Blocking the load on pending writes
    // used to lock the user out of loading any new batch whenever a flush
    // kept failing.
    dirtyCheckpointRef.current.clear();
    queueStore.replace(typeof next === "function" ? next(queueStore.items) : next);
    const firstChain = queueStore.items[0]?.chainId;
    if (firstChain && queueStore.items.every((item) => item.chainId === firstChain)) setSelectedChainId(firstChain);
    reportCacheRef.current.clear();
    checkpoint(queueStore.items.map((item, index) => [index, item]), true);
    setQueueRevision((v) => v + 1);
    return true;
  }, [queueStore, checkpoint, showNotice]);

  useEffect(() => {
    let canceled = false;
    checkpointReadyRef.current = initializeBatchQueue(queueStore, {
      isCurrent: () => !canceled,
      loadLegacy: () => {
        try {
          const raw = localStorage.getItem("kiln_active_batch_queue");
          return raw ? JSON.parse(raw) as BatchItem[] : null;
        } catch { return null; }
      },
    }).then((changed) => {
      if (changed && !canceled) {
        const firstChain = queueStore.items[0]?.chainId;
        if (firstChain && queueStore.items.every((item) => item.chainId === firstChain)) setSelectedChainId(firstChain);
        setQueueRevision((v) => v + 1);
      }
    }).catch((err: unknown) => {
      if (!canceled) setCheckpointError(err instanceof Error ? err.message : String(err));
    });
    return () => { canceled = true; };
  }, [queueStore]);

  const handleNetworkChange = (chainId: string) => {
    if (runnerActiveRef.current) return;
    if (!setQueue(retargetBatchQueue(queueStore.items, chainId))) return;
    setSelectedChainId(chainId);
    setCurrentIndex(-1);
    setCurrentPage(1);
  };

  // Copy helper
  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Ultra-fast zero-allocation address count
  const parsedCount = useMemo(() => {
    if (fileMeta) return fileMeta.count;
    return countValidAddresses(inputText);
  }, [inputText, fileMeta]);

  // Parse text into queue
  const handleLoadNewBatch = () => {
    if (runnerActiveRef.current) return;
    const parsed = parseAddressList(inputText, selectedChainId);
    if (!setQueue(parsed)) return;
    setFileMeta(null);
    setIsRunning(false);
    setCurrentIndex(-1);
    setCurrentPage(1);
  };

  // Upload multiline file (optimized for 50,000+ lines)
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (runnerActiveRef.current) return;
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content && !runnerActiveRef.current) {
        const parsed = parseAddressList(content, selectedChainId);
        if (!setQueue(parsed)) return;
        setIsRunning(false);
        setCurrentIndex(-1);
        setCurrentPage(1);

        if (parsed.length > 250) {
          // Large file optimization: do not choke React textarea with 50,000 DOM lines
          setFileMeta({
            name: file.name,
            count: parsed.length,
            sizeKb: Math.round(file.size / 1024),
          });
          const previewSnippet = content.slice(0, 8000).split(/\r?\n/).slice(0, 25).join("\n");
          setInputText(`${previewSnippet}\n\n# ... [${(parsed.length - 25).toLocaleString()} more addresses loaded from "${file.name}"]`);
        } else {
          setFileMeta(null);
          setInputText(content);
        }
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const publishWriterStats = useCallback(() => {
    if (!mountedRef.current) return;
    const local = localWriterRef.current?.stats;
    const remote = remoteWriterRef.current?.stats;
    setDbSyncStats({
      totalFlushed: local?.totalFlushed ?? 0,
      pendingCount: (local?.pendingCount ?? 0) + (remote?.pendingCount ?? 0),
      isFlushing: Boolean(local?.isFlushing || remote?.isFlushing),
      lastError: local?.lastError ?? remote?.lastError ?? null,
    });
  }, []);

  const ensureLocalWriter = useCallback(() => {
    localWriterRef.current ??= new AsyncBatchWriter<ComprehensiveRecordInput>({
      maxBatchBytes: 1_400_000,
      write: async (records) => {
        const result = await saveBatchComprehensiveScansFn({ data: { records } });
        if (result.savedCount !== records.length) throw new Error("Database did not acknowledge the complete batch");
        for (const record of records) {
          const index = pendingIndexesRef.current.get(record.id!);
          if (index !== undefined && queueStore.items[index]?.scanId === record.id) {
            updateQueueItem(index, { persisted: true });
          }
          pendingIndexesRef.current.delete(record.id!);
        }
      },
      onChange: publishWriterStats,
    });
    return localWriterRef.current;
  }, [queueStore, updateQueueItem, publishWriterStats]);

  const ensureRemoteWriter = useCallback(() => {
    if (!savedSupabaseCfgRef.current.enabled) return null;
    remoteWriterRef.current ??= createSupabaseBatchWriter(
      () => savedSupabaseCfgRef.current, publishWriterStats,
      (rows) => {
        for (const row of rows) {
          const index = pendingRemoteIndexesRef.current.get(row.id);
          if (index !== undefined && queueStore.items[index]?.scanId === row.id) updateQueueItem(index, { supabaseSynced: true });
          pendingRemoteIndexesRef.current.delete(row.id);
        }
      },
    );
    return remoteWriterRef.current;
  }, [publishWriterStats, queueStore, updateQueueItem]);

  const replayRemoteOutbox = useCallback((): Promise<void> => {
    if (remoteReplayRef.current) return remoteReplayRef.current;
    const writer = ensureRemoteWriter();
    if (!writer) return Promise.resolve();
    remoteReplayRef.current = (async () => {
      await writer.flush();
      for (let index = 0; index < queueStore.items.length; index++) {
        const item = queueStore.items[index];
        if (item.status !== "completed" || item.supabaseSynced !== false) continue;
        const row = toSupabaseBatchRow(item);
        if (pendingRemoteIndexesRef.current.has(row.id)) continue;
        pendingRemoteIndexesRef.current.set(row.id, index);
        try { await writer.enqueue(row); }
        catch (err) { pendingRemoteIndexesRef.current.delete(row.id); throw err; }
      }
      await writer.flush();
    })().finally(() => { remoteReplayRef.current = null; });
    return remoteReplayRef.current;
  }, [ensureRemoteWriter, queueStore]);

  const flushDbBuffer = useCallback(async () => {
    try {
      const results = await Promise.allSettled([
        localWriterRef.current?.flush(), replayRemoteOutbox(),
      ]);
      repaintQueue();
      const failure = results.find((r) => r.status === "rejected");
      if (failure?.status === "rejected") {
        console.warn("[pipeline] buffer flush notice:", failure.reason);
        setDbSyncStats((previous) => ({
          ...previous,
          lastError: failure.reason instanceof Error ? failure.reason.message : String(failure.reason),
        }));
      }
    } catch (err) {
      console.warn("[pipeline] flushDbBuffer error:", err);
    }
  }, [repaintQueue, replayRemoteOutbox]);

  useEffect(() => {
    mountedRef.current = true;
    const beforeUnload = (event: BeforeUnloadEvent) => {
      if (checkpointPendingRef.current > 0 || dirtyCheckpointRef.current.size > 0 ||
        (localWriterRef.current?.stats.pendingCount ?? 0) + (remoteWriterRef.current?.stats.pendingCount ?? 0) > 0) {
        event.preventDefault(); event.returnValue = "";
      }
    };
    // Flush when the browser tab is hidden or the page is being put away —
    // unmount cleanup alone is fire-and-forget and can be cut off mid-flight.
    const flushOnHidden = () => {
      if (document.visibilityState === "hidden") void flushDbBuffer().catch(() => undefined);
    };
    const flushOnPageHide = () => { void flushDbBuffer().catch(() => undefined); };
    window.addEventListener("beforeunload", beforeUnload);
    document.addEventListener("visibilitychange", flushOnHidden);
    window.addEventListener("pagehide", flushOnPageHide);
    return () => {
      isRunningRef.current = false;
      mountedRef.current = false;
      if (repaintTimerRef.current) clearTimeout(repaintTimerRef.current);
      repaintQueue();
      localWriterRef.current?.dispose(); remoteWriterRef.current?.dispose();
      void flushDbBuffer().catch(() => undefined);
      window.removeEventListener("beforeunload", beforeUnload);
      document.removeEventListener("visibilitychange", flushOnHidden);
      window.removeEventListener("pagehide", flushOnPageHide);
    };
  }, [flushDbBuffer, repaintQueue]);

  // On-demand inspection handler
  const handleInspect = async (item: BatchItem) => {
    const cached = reportCacheRef.current.get(`${item.chainId}:${item.address.toLowerCase()}`);
    if (cached) {
      onInspectItem(cached.report, cached.rawBody, item.label);
      return;
    }

    setInspectingAddr(item.address);
    try {
      const fresh = await analyzeAddress(item.address, item.chainId, item.label);
      reportCacheRef.current.set(`${item.chainId}:${item.address.toLowerCase()}`, {
        report: fresh.report,
        rawBody: fresh.rawBody,
      });
      onInspectItem(fresh.report, fresh.rawBody, item.label);
    } catch (err) {
      showNotice("Could not load full report for inspection: " + (err instanceof Error ? err.message : String(err)), false);
    } finally {
      setInspectingAddr(null);
    }
  };

  // Address fetches stay rate-limited; persistence overlaps through bounded writers.
  const startPipeline = async () => {
    if (runnerActiveRef.current) return;
    runnerActiveRef.current = true;
    isRunningRef.current = true;
    setIsRunning(true);
    const localWriter = ensureLocalWriter();
    localWriter.clearError();
    remoteWriterRef.current?.clearError();
    try {
      try {
        await checkpointReadyRef.current;
      } catch (cpErr) {
        console.warn("[pipeline] checkpoint ready notice:", cpErr);
      }
      try {
        await checkpointChainRef.current;
      } catch (chainErr) {
        console.warn("[pipeline] checkpoint chain notice:", chainErr);
      }
      // Finish a paused run's pending writes before attempting completed addresses again.
      try {
        await flushDbBuffer();
      } catch (flushErr) {
        console.warn("[pipeline] pre-flush notice:", flushErr);
      }
      const remoteWriter = ensureRemoteWriter();
      const items = queueStore.items;
      for (let i = 0; i < items.length && isRunningRef.current; i++) {
        const item = items[i];
        if (!item || item.status === "completed") continue;
        setCurrentIndex(i);
        const scanId = item.scanId ?? crypto.randomUUID();
        updateQueueItem(i, { status: "analyzing", error: undefined, scanId, persisted: false });
        // Proxy detection + view probes start now so they run in parallel
        // with the analysis; both are best-effort and never fail the item.
        const proxyPromise = detectProxyArchitecture(item.address, item.chainId).then(
          (value) => ({ status: "fulfilled" as const, value }),
          (reason: unknown) => ({ status: "rejected" as const, reason }),
        );
        const probePromise = probeContractInterfaces(item.address, item.chainId).then(
          (value) => ({ status: "fulfilled" as const, value }),
          (reason: unknown) => ({ status: "rejected" as const, reason }),
        );
        // Analyze with retries: every queued address is a contract, so a
        // failure here is a transient provider hiccup, not a dead address.
        let result: Awaited<ReturnType<typeof analyzeAddress>>;
        try {
          result = await withRetry(() => analyzeAddress(item.address, item.chainId, item.label), {
            retries: 2, baseDelayMs: 2000, retryOn: () => true,
          });
        } catch (err) {
          updateQueueItem(i, { status: "failed", error: err instanceof Error ? err.message : String(err) });
          if (delayMs > 0 && isRunningRef.current) await new Promise((resolve) => setTimeout(resolve, delayMs));
          continue;
        }
        const [proxyOutcome, probeOutcome] = await Promise.all([proxyPromise, probePromise]);
        const proxyInfo = proxyOutcome.status === "fulfilled" ? proxyOutcome.value : null;
        const probes = probeOutcome.status === "fulfilled" ? probeOutcome.value : [];
        // Opt-in OpenRouter second pass, per item (keeps the bulk save fast —
        // a bulk save with per-record LLM calls blows the function timeout
        // and stalls the flush at 0 records). Never fails the item.
        if (aiSecondPass) {
          try {
            const pass = await runSecondPassFn({ data: { report: result.report, body: result.rawBody } });
            if (pass.text) result.report.aiNarrative = pass.text;
            result.report.aiStatus = pass.status;
          } catch (err) {
            console.warn("[pipeline] AI second pass notice:", err);
          }
        }
        if (!mountedRef.current) break;
        const counts = { critical: 0, high: 0 };
        for (const finding of result.report.findings) {
          if (finding.severity === "critical" || finding.severity === "high") counts[finding.severity]++;
        }
        const updatedItem: BatchItem = {
          ...items[i], status: "completed", inputKind: result.inputKind,
          supabaseSynced: !remoteWriter, summary: result.report.summary,
          bytecodeSize: result.report.inventory.bytecodeBytes ?? result.rawBody.length / 2,
          riskScore: result.report.riskScore, findingsCount: result.report.findings.length,
          criticalCount: counts.critical, highCount: counts.high, completedAt: new Date().toISOString(),
        };
        reportCacheRef.current.set(`${item.chainId}:${item.address.toLowerCase()}`, {
          report: result.report, rawBody: result.rawBody,
        });
        pendingIndexesRef.current.set(scanId, i);
        let localEnqueued = false;
        try {
          await localWriter.enqueue({
            id: scanId, label: updatedItem.label, report: result.report, body: result.rawBody,
            targetAddress: item.address, chainId: item.chainId,
            compilerVersion: result.report.inventory.compiler, sourceOrigin: "pipeline", indexToRag: true,
            proxyInfo, probes,
          });
          localEnqueued = true;
          updateQueueItem(i, { ...updatedItem, persisted: items[i].persisted });
          if (remoteWriter) {
            pendingRemoteIndexesRef.current.set(scanId, i);
            try { await remoteWriter.enqueue(toSupabaseBatchRow(updatedItem)); }
            catch (err) { pendingRemoteIndexesRef.current.delete(scanId); throw err; }
          }
        } catch (err) {
          if (!localEnqueued) pendingIndexesRef.current.delete(scanId);
          console.warn("[pipeline] buffer enqueue notice:", err);
          updateQueueItem(i, {
            ...updatedItem,
            persisted: false,
            error: err instanceof Error ? err.message : String(err),
          });
        }
        if (delayMs > 0 && i < items.length - 1 && isRunningRef.current) {
          await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
      }
      try {
        await flushDbBuffer();
      } catch (flushErr) {
        console.warn("[pipeline] post-flush notice:", flushErr);
      }
    } catch (err) {
      if (mountedRef.current) setDbSyncStats((previous) => ({ ...previous,
        lastError: err instanceof Error ? err.message : String(err),
      }));
    } finally {
      isRunningRef.current = false; runnerActiveRef.current = false;
      repaintQueue();
      if (mountedRef.current) { setIsRunning(false); setIsPausing(false); setCurrentIndex(-1); }
    }
  };

  const pausePipeline = () => {
    if (!isRunningRef.current) return;
    setIsPausing(true);
    isRunningRef.current = false;
    void flushDbBuffer().catch(() => undefined);
  };

  // Resume or load from Supabase database
  const handleResumeSupabase = async () => {
    setIsResumingSupabase(true);
    try {
      let loadedCount = 0;
      let matchedCount = 0;

      // 1. Load directly from Supabase PostgreSQL archive
      try {
        const storedScans = await listScans();
        if (storedScans && storedScans.length > 0) {
          const map = new Map<string, BatchItem>();
          queueStore.items.forEach((p) => map.set(`${p.chainId}:${p.address.toLowerCase()}`, p));

          for (const scan of storedScans) {
            if (!scan.targetAddress) continue;
            const key = `${scan.chainId || "ethereum"}:${scan.targetAddress.toLowerCase()}`;
            const existing = map.get(key);
            loadedCount++;
            if (existing) {
              matchedCount++;
              map.set(key, {
                ...existing,
                status: "completed",
                riskScore: scan.riskScore,
                findingsCount: scan.criticalCount + scan.highCount + scan.mediumCount + scan.lowCount + scan.infoCount,
                criticalCount: scan.criticalCount,
                highCount: scan.highCount,
                persisted: true,
                supabaseSynced: true,
                completedAt: scan.createdAt,
              });
            } else {
              map.set(key, {
                id: scan.id,
                scanId: scan.id,
                address: scan.targetAddress,
                label: scan.label || scan.contractName || scan.targetAddress,
                chainId: scan.chainId || "ethereum",
                status: "completed",
                riskScore: scan.riskScore,
                findingsCount: scan.criticalCount + scan.highCount + scan.mediumCount + scan.lowCount + scan.infoCount,
                criticalCount: scan.criticalCount,
                highCount: scan.highCount,
                persisted: true,
                supabaseSynced: true,
                completedAt: scan.createdAt,
              });
            }
          }

          const updatedList = Array.from(map.values());
          dirtyCheckpointRef.current.clear();
          queueStore.replace(updatedList);
          checkpoint(queueStore.items.map((item, index) => [index, item]), true);
          setQueueRevision((v) => v + 1);
        }
      } catch (dbErr) {
        console.warn("[pipeline] Supabase DB listScans error:", dbErr);
      }

      // 2. Also merge from Supabase REST endpoint if configured
      if (supabaseCfg.enabled && supabaseCfg.url && supabaseCfg.anonKey) {
        try {
          const remoteItems = await loadBatchFromSupabase(supabaseCfg);
          if (remoteItems.length > 0) {
            const map = new Map<string, BatchItem>();
            queueStore.items.forEach((p) => map.set(`${p.chainId}:${p.address.toLowerCase()}`, p));
            remoteItems.forEach((r) => {
              const key = `${r.chainId}:${r.address.toLowerCase()}`;
              if (map.has(key)) matchedCount++;
              map.set(key, { ...r, persisted: true, supabaseSynced: true });
              loadedCount++;
            });
            dirtyCheckpointRef.current.clear();
            queueStore.replace(Array.from(map.values()));
            checkpoint(queueStore.items.map((item, index) => [index, item]), true);
            setQueueRevision((v) => v + 1);
          }
        } catch (restErr) {
          console.warn("[pipeline] REST Supabase load error:", restErr);
        }
      }

      if (loadedCount > 0) {
        showNotice(`Resumed from Supabase: ${loadedCount} audits indexed (${matchedCount} in current queue marked complete).`);
      } else {
        showNotice("No prior audits found in Supabase database to resume from.", false);
      }
    } catch (err) {
      showNotice("Failed to resume from Supabase: " + (err instanceof Error ? err.message : String(err)), false);
    } finally {
      setIsResumingSupabase(false);
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
    if (runnerActiveRef.current || remoteWriterRef.current?.stats.isFlushing) {
      setSupabaseStatusMsg({ ok: false, msg: "Pause the pipeline and wait for the active write before changing its connection." });
      return;
    }
    try {
      saveStoredSupabaseConfig(supabaseCfg);
      savedSupabaseCfgRef.current = { ...supabaseCfg };
      setIsSupabaseModalOpen(false);
    } catch (err) {
      setSupabaseStatusMsg({ ok: false, msg: err instanceof Error ? err.message : String(err) });
    }
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
  const { completed, failed, pending, totalCrit, totalHigh } = queueStore.summary;
  const pendingWriteCount = Math.max(dbSyncStats.pendingCount, queueStore.summary.unsynced);
  const percent = total > 0 ? Math.round((completed / total) * 100) : 0;

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
  }, [queue, queueRevision, filterQuery]);

  // Pagination calculations for handling 50,000+ items smoothly
  const totalPages = Math.max(1, Math.ceil(filteredQueue.length / pageSize));
  const safeCurrentPage = Math.min(Math.max(1, currentPage), totalPages);

  // Sliced items for the current page only
  const paginatedQueue = useMemo(() => {
    const start = (safeCurrentPage - 1) * pageSize;
    return filteredQueue.slice(start, start + pageSize);
  }, [filteredQueue, queueRevision, safeCurrentPage, pageSize]);

  const displayChainId = useMemo(() => {
    const firstChain = queue[0]?.chainId;
    return firstChain && queue.some((item) => item.chainId !== firstChain) ? "mixed" : firstChain ?? selectedChainId;
  }, [queue, selectedChainId]);

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

      {/* Headless pipeline worker (Termux) — survives browser close. */}
      <PipelineWorkerStatus />

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
                <label className="text-[#a39886] text-[10px] uppercase block mb-1">Supabase Publishable / Anon Key</label>
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
              <div className="p-3 rounded-lg bg-[#12110e] border border-[#3a3428] flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-[#e8a54b] font-bold block">Direct PostgreSQL DB Wiring</span>
                  <span className="text-[10px] text-[#a39886]">Connect direct Supabase Postgres for project SmartKontrakt</span>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setIsSupabaseModalOpen(false);
                    setIsDbWiringModalOpen(true);
                  }}
                  className="px-2.5 py-1 rounded bg-[#3a2c14] hover:bg-[#4a391c] border border-[#e8a54b]/40 text-[#e8a54b] text-[10px] font-bold transition-colors"
                >
                  Configure DB &rarr;
                </button>
              </div>
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

      {/* Direct PostgreSQL DB Modal */}
      <SupabaseDbModal
        isOpen={isDbWiringModalOpen}
        onClose={() => setIsDbWiringModalOpen(false)}
      />

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
                disabled={queue.length === 0 || (completed === total && queueStore.summary.unsynced === 0)}
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
                onClick={() => {
                  queueStore.items.forEach((item, idx) => {
                    if (item.status === "failed") {
                      updateQueueItem(idx, { status: "pending", error: undefined });
                    }
                  });
                  repaintQueue();
                  showNotice(`Reset ${failed} failed items back to pending queue.`);
                }}
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

      {/* Multiline Address Input Box & Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Multiline Text Ingestion */}
        <div className="lg:col-span-5 bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-[#e8a54b]" />
              <h3 className="text-xs font-mono font-bold text-[#f4efe6] uppercase">
                Input Addresses (CSV or 1 per line)
              </h3>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <button
                onClick={() => fileInputRef.current?.click()}
                className="px-2.5 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[11px] font-mono text-[#f4efe6] flex items-center gap-1 transition-colors"
                title="Upload .csv or .txt (parses 1st column)"
              >
                <Upload className="w-3 h-3 text-[#e8a54b]" />
                <span>Upload .csv / .txt</span>
              </button>
              <button
                onClick={() => {
                  setFileMeta(null);
                  setInputText(SAMPLE_BATCH_INPUT);
                }}
                className="px-2 py-1 text-[11px] font-mono text-[#a39886] hover:text-[#f4efe6]"
              >
                Reset Sample
              </button>
            </div>
          </div>

          {fileMeta && (
            <div className="flex items-center justify-between bg-[#26231c] border border-[#e8a54b]/40 rounded-lg p-2.5 text-xs font-mono text-[#e8a54b]">
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-[#e8a54b] shrink-0" />
                <span className="truncate">
                  <strong>{fileMeta.name}</strong> ({fileMeta.count.toLocaleString()} contracts, {fileMeta.sizeKb} KB) loaded in streaming memory mode
                </span>
              </div>
              <button
                onClick={() => {
                  setFileMeta(null);
                  setInputText(SAMPLE_BATCH_INPUT);
                  setQueue(parseAddressList(SAMPLE_BATCH_INPUT, selectedChainId));
                  setCurrentPage(1);
                }}
                className="text-[#a39886] hover:text-[#f4efe6] underline text-[11px] ml-2 shrink-0"
              >
                Clear File
              </button>
            </div>
          )}

          <textarea
            value={inputText}
            onChange={(e) => {
              setInputText(e.target.value);
              if (fileMeta) setFileMeta(null);
            }}
            placeholder={`ContractAddress,Name,Chain\n0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984,Uniswap Token,ethereum\n0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D,Router02,ethereum`}
            spellCheck={false}
            className="w-full h-56 bg-[#12110e] border border-[#3a3428] rounded-lg p-3 font-mono text-xs text-[#f4efe6] focus:outline-none focus:border-[#e8a54b] leading-relaxed resize-none"
          />

          <div className="flex items-center justify-between text-xs font-mono text-[#a39886]">
            <span>
              Parsed {parsedCount.toLocaleString()} valid addresses
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
                  paginatedQueue.map((item, idx) => {
                    const rowNumber = (safeCurrentPage - 1) * pageSize + idx + 1;
                    const isCurrent = rowNumber - 1 === currentIndex && isRunning;
                    return (
                      <tr
                        key={item.id}
                        className={`hover:bg-[#26231c]/50 transition-colors ${
                          isCurrent ? "bg-[#3a2c14]/40" : ""
                        }`}
                      >
                        <td className="p-2.5 text-[#746c60]">{rowNumber}</td>
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
                              href={`${(SUPPORTED_CHAINS.find((chain) => chain.id === item.chainId) ?? activeChainObj).blockExplorer}/address/${item.address}`}
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
                          {item.status === "completed" ? (
                            <button
                              onClick={() => handleInspect(item)}
                              disabled={inspectingAddr === item.address}
                              className="px-2 py-1 rounded bg-[#3a2c14] hover:bg-[#e8a54b] hover:text-[#12110e] text-[#e8a54b] text-[11px] font-bold flex items-center gap-1 ml-auto transition-colors disabled:opacity-50"
                              title="Inspect full audit in Workbench"
                            >
                              {inspectingAddr === item.address ? (
                                <Loader2 className="w-3 h-3 animate-spin" />
                              ) : (
                                <Eye className="w-3 h-3" />
                              )}
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

          {/* Table Pagination & Windowing Controls (handles 50,000+ rows smoothly) */}
          {filteredQueue.length > 0 && (
            <div className="flex items-center justify-between flex-wrap gap-3 pt-2 text-xs font-mono text-[#a39886] border-t border-[#3a3428]">
              <div className="flex items-center gap-2">
                <span>
                  Showing {((safeCurrentPage - 1) * pageSize + 1).toLocaleString()} -{" "}
                  {Math.min(safeCurrentPage * pageSize, filteredQueue.length).toLocaleString()} of{" "}
                  <strong className="text-[#f4efe6]">{filteredQueue.length.toLocaleString()}</strong> contracts
                </span>
                <span className="text-[#746c60]">|</span>
                <div className="flex items-center gap-1">
                  <span>Page Size:</span>
                  <select
                    value={pageSize}
                    onChange={(e) => {
                      setPageSize(Number(e.target.value));
                      setCurrentPage(1);
                    }}
                    className="bg-[#12110e] border border-[#3a3428] rounded px-1.5 py-0.5 text-[#f4efe6] focus:outline-none"
                  >
                    <option value={25}>25</option>
                    <option value={50}>50</option>
                    <option value={100}>100</option>
                    <option value={250}>250</option>
                  </select>
                </div>
              </div>

              {/* Navigation buttons */}
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setCurrentPage(1)}
                  disabled={safeCurrentPage === 1}
                  className="p-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] disabled:opacity-30 disabled:pointer-events-none"
                  title="First Page"
                >
                  <ChevronsLeft className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  disabled={safeCurrentPage === 1}
                  className="p-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] disabled:opacity-30 disabled:pointer-events-none"
                  title="Previous Page"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                </button>

                <div className="flex items-center gap-1 px-1.5 text-[#f4efe6]">
                  <span>Page</span>
                  <input
                    type="number"
                    min={1}
                    max={totalPages}
                    value={jumpPageInput !== "" ? jumpPageInput : safeCurrentPage}
                    onChange={(e) => setJumpPageInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        const val = parseInt(jumpPageInput, 10);
                        if (!isNaN(val) && val >= 1 && val <= totalPages) {
                          setCurrentPage(val);
                        }
                        setJumpPageInput("");
                      }
                    }}
                    onBlur={() => {
                      if (jumpPageInput !== "") {
                        const val = parseInt(jumpPageInput, 10);
                        if (!isNaN(val) && val >= 1 && val <= totalPages) {
                          setCurrentPage(val);
                        }
                        setJumpPageInput("");
                      }
                    }}
                    className="w-12 text-center bg-[#12110e] border border-[#3a3428] rounded px-1 py-0.5 text-xs text-[#e8a54b] focus:outline-none focus:border-[#e8a54b]"
                  />
                  <span>of {totalPages.toLocaleString()}</span>
                </div>

                <button
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  disabled={safeCurrentPage === totalPages}
                  className="p-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] disabled:opacity-30 disabled:pointer-events-none"
                  title="Next Page"
                >
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => setCurrentPage(totalPages)}
                  disabled={safeCurrentPage === totalPages}
                  className="p-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] disabled:opacity-30 disabled:pointer-events-none"
                  title="Last Page"
                >
                  <ChevronsRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
