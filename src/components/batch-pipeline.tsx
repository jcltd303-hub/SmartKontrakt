import { PipelineConnectionModal } from "./batch-pipeline/PipelineConnectionModal";
import { PipelineControls } from "./batch-pipeline/PipelineControls";
import { PipelineAddressInput } from "./batch-pipeline/PipelineAddressInput";
import { PipelineQueueTable } from "./batch-pipeline/PipelineQueueTable";
import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import {
  parseAddressList,
  countValidAddresses,
  analyzeAddress,
  SUPPORTED_CHAINS,
  type BatchItem,
} from "@/lib/audit/address-fetcher";
import { isStaleVersion } from "@/lib/audit/analyzer-version";
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
import { runResnetBrowser } from "@/lib/image-ml/run-resnet-browser";
import { BatchQueue, retargetBatchQueue } from "@/lib/audit/batch-queue";
import { initializeBatchQueue, saveBatchCheckpoint } from "@/lib/audit/batch-checkpoint";
import type { Report } from "@/lib/audit/types";
import { saveBatchComprehensiveScansFn, listScans } from "@/lib/scans.functions";
import type { ComprehensiveRecordInput } from "@/lib/audit/persist.server";
import { SupabaseDbModal } from "./supabase-db-modal";
import { PipelineWorkerStatus } from "./pipeline-worker-status";

interface BatchPipelineProps {
  active?: boolean;
  onInspectItem: (report: Report, rawBody: string, label: string) => void;
}

const SAMPLE_BATCH_INPUT = `# High-profile EVM contracts for security analysis
0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D # Uniswap V2 Router02
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 # WETH9 Wrapped Ether
0xdAC17F958D2ee523a2206206994597C13D831ec7 # Tether USD (USDT)
0x6B175474E89094C44Da98b954EedeAC495271d0F # Dai Stablecoin (DAI)
0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7 # Curve.fi 3pool`;

export function BatchPipeline({ onInspectItem, active = true }: BatchPipelineProps) {
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
      const fresh = await analyzeAddress(item.address, item.chainId, item.label, {
        resnetRunner: runResnetBrowser,
      });
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
          result = await withRetry(() => analyzeAddress(item.address, item.chainId, item.label, {
            resnetRunner: runResnetBrowser,
          }), {
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
          balanceWei: result.report.inventory.balanceWei ?? null,
          valueUsd: result.report.inventory.valueUsd ?? null,
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
      // Records produced by an older analyzer. They are NOT marked complete:
      // leaving them pending is what makes a freshen run re-analyze them.
      let staleCount = 0;

      // 1. Load directly from Supabase PostgreSQL archive
      try {
        const storedScans = (await listScans()).summaries;
        if (storedScans && storedScans.length > 0) {
          const map = new Map<string, BatchItem>();
          queueStore.items.forEach((p) => map.set(`${p.chainId}:${p.address.toLowerCase()}`, p));

          for (const scan of storedScans) {
            if (!scan.targetAddress) continue;
            const key = `${scan.chainId || "ethereum"}:${scan.targetAddress.toLowerCase()}`;
            const existing = map.get(key);
            const stale = isStaleVersion(scan.analyzerVersion);
            if (stale) staleCount++;
            loadedCount++;
            if (existing) {
              matchedCount++;
              map.set(key, {
                ...existing,
                // Stale: keep it pending so the next run refreshes it rather
                // than treating an older analyzer's verdict as final.
                status: stale ? "pending" : "completed",
                riskScore: scan.riskScore,
                balanceWei: scan.balanceWei ?? null,
                valueUsd: scan.valueUsd ?? null,
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
                status: stale ? "pending" : "completed",
                riskScore: scan.riskScore,
                balanceWei: scan.balanceWei ?? null,
                valueUsd: scan.valueUsd ?? null,
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
        showNotice(
          `Resumed from Supabase: ${loadedCount} audits indexed (${matchedCount} in current queue). ` +
          (staleCount > 0
            ? `${staleCount} were produced by an older analyzer and stay pending — start a run to refresh them.`
            : "All are current."),
        );
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

  const retryFailed = () => {
    queueStore.items.forEach((item, idx) => {
      if (item.status === "failed") updateQueueItem(idx, { status: "pending", error: undefined });
    });
    repaintQueue();
    showNotice(`Reset ${failed} failed items back to pending queue.`);
  };

  // Progress calculations
  const total = queue.length;
  const { completed, failed, pending, totalCrit, totalHigh } = queueStore.summary;
  const pendingWriteCount = Math.max(dbSyncStats.pendingCount, queueStore.summary.unsynced);
  const percent = total > 0 ? Math.round((completed / total) * 100) : 0;

  // Filtered queue items
  const filteredQueue = useMemo(() => {
    // queueRevision is a cache-bust, not a redundant dep: the queue is mutated
    // in place on status updates, so its array identity does not change and
    // this memo would serve a stale list. Referencing it keeps that explicit.
    void queueRevision;
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
    void queueRevision;
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
      <PipelineWorkerStatus active={active} />

      {/* Supabase Connection Modal */}
      <PipelineConnectionModal
        isSupabaseModalOpen={isSupabaseModalOpen}
        setIsSupabaseModalOpen={setIsSupabaseModalOpen}
        setIsDbWiringModalOpen={setIsDbWiringModalOpen}
        supabaseCfg={supabaseCfg}
        setSupabaseCfg={setSupabaseCfg}
        supabaseStatusMsg={supabaseStatusMsg}
        isTestingSupabase={isTestingSupabase}
        handleTestSupabase={handleTestSupabase}
        handleSaveSupabaseConfig={handleSaveSupabaseConfig}
      />

      {/* Direct PostgreSQL DB Modal */}
      <SupabaseDbModal
        isOpen={isDbWiringModalOpen}
        onClose={() => setIsDbWiringModalOpen(false)}
      />

      <PipelineControls
        displayChainId={displayChainId}
        handleNetworkChange={handleNetworkChange}
        isRunning={isRunning}
        setIsSupabaseModalOpen={setIsSupabaseModalOpen}
        setIsDbWiringModalOpen={setIsDbWiringModalOpen}
        supabaseCfg={supabaseCfg}
        actionNotice={actionNotice}
        setActionNotice={setActionNotice}
        startPipeline={startPipeline}
        pausePipeline={pausePipeline}
        isPausing={isPausing}
        total={total}
        completed={completed}
        failed={failed}
        pending={pending}
        totalCrit={totalCrit}
        totalHigh={totalHigh}
        percent={percent}
        unsynced={queueStore.summary.unsynced}
        retryFailed={retryFailed}
        handleLoadNewBatch={handleLoadNewBatch}
        handleResumeSupabase={handleResumeSupabase}
        isResumingSupabase={isResumingSupabase}
        delayMs={delayMs}
        setDelayMs={setDelayMs}
        aiSecondPass={aiSecondPass}
        setAiSecondPass={setAiSecondPass}
        dbSyncStats={dbSyncStats}
        pendingWriteCount={pendingWriteCount}
        checkpointError={checkpointError}
        flushDbBuffer={flushDbBuffer}
      />

      {/* Multiline Address Input Box & Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <PipelineAddressInput
          fileInputRef={fileInputRef}
          setFileMeta={setFileMeta}
          setInputText={setInputText}
          fileMeta={fileMeta}
          inputText={inputText}
          sampleInput={SAMPLE_BATCH_INPUT}
          selectedChainId={selectedChainId}
          setQueue={setQueue}
          setCurrentPage={setCurrentPage}
          parsedCount={parsedCount}
          handleLoadNewBatch={handleLoadNewBatch}
        />

        <PipelineQueueTable
          queue={queue}
          isRunning={isRunning}
          filterQuery={filterQuery}
          setFilterQuery={setFilterQuery}
          exportCsv={exportCsv}
          exportJson={exportJson}
          filteredQueue={filteredQueue}
          paginatedQueue={paginatedQueue}
          safeCurrentPage={safeCurrentPage}
          pageSize={pageSize}
          currentIndex={currentIndex}
          copyText={copyText}
          copiedKey={copiedKey}
          activeChainObj={activeChainObj}
          handleInspect={handleInspect}
          inspectingAddr={inspectingAddr}
          setPageSize={setPageSize}
          setCurrentPage={setCurrentPage}
          totalPages={totalPages}
          jumpPageInput={jumpPageInput}
          setJumpPageInput={setJumpPageInput}
        />

      </div>
    </div>
  );
}
