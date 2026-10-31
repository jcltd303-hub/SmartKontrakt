/**
 * SmartKontrakt pipeline worker — headless address-pipeline runner.
 *
 * The browser pipeline dies when the browser closes (its checkpoint lives
 * in IndexedDB). This worker runs the SAME per-item loop in Node on Jer's
 * phone (proot Ubuntu in Termux), survives browser close, and saves to the
 * same Supabase tables. The browser Address Pipeline tab becomes a monitor.
 *
 * Run:  cd <repo root> && bash pipeline-worker/start.sh
 *       (or: npx -y tsx pipeline-worker/worker.ts)
 *
 * Why the lib imports below are dynamic: src/lib/db.ts reads DATABASE_URL
 * at import time, so pipeline-worker/.env MUST be loaded first. Static
 * imports would run before the dotenv loader below. Type-only imports are
 * erased at compile time, so they are safe as static imports.
 *
 * Control API (loopback only, same pattern as termux-backend/server.mjs):
 *   GET  /status   — state, totals, current address, last flush/error
 *   POST /start    — { addressesFile, chainId?, aiSecondPass?, delayMs?,
 *                     deepAgent?, deepAgentMaxItems?, deepAgentMinSeverity?,
 *                     autoPoc? }
 *                     autoPoc (default ON) runs the adjudication chain —
 *                     LLM-gen -> Foundry run -> Supabase save — for every
 *                     PoC-eligible high/critical finding right after its
 *                     entry is persisted. There is NO attempt cap — every
 *                     PoC-eligible finding is attempted (identical-code
 *                     shared saves cost nothing). A circuit breaker stops
 *                     auto-PoC for the run after 3 consecutive
 *                     backend-infra failures.
 *                     deepAgent runs the Deep Agent loop (propose ->
 *                     fork-PoC -> reward -> deeper) for flagged addresses
 *                     only: >= 1 finding at deepAgentMinSeverity
 *                     (default "high"). deepAgentMaxItems caps how many
 *                     addresses get the agent per run (default 250,
 *                     0 = unlimited). PoCs run via the Foundry backend
 *                     (:8787, FOUNDRY_BACKEND_URL).
 *   POST /pause    — stop after the current item, flush, keep the run to resume
 *   POST /resume   — continue a paused run
 *   POST /stop     — finish the current item, flush, drop the run
 *
 * Resume needs no checkpoint file: on /start the worker queries Supabase
 * for already-saved (chain, address) pairs and skips them — the same
 * resume semantics as the browser's handleResumeSupabase.
 */

import http from "node:http";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import v8 from "node:v8";

import type { BatchItem } from "../src/lib/audit/address-fetcher.ts";
import { valueCacheStats } from "../src/lib/audit/value.ts";
import { encodePostgresCredentials } from "../src/lib/pg-url.ts";
import { analyzerStamp } from "../src/lib/audit/analyzer-version.ts";
import { assertFreshnessSchema, savedScanVersions, scanFreshness, shouldSkipInRun } from "../src/lib/audit/scan-freshness.server.ts";
import type { ComprehensiveRecordInput } from "../src/lib/audit/persist.server.ts";

// ---------------------------------------------------------------- .env ----
// Tiny dotenv parser, no dependency. pipeline-worker/.env only; existing
// process.env wins. Must run before the lib imports below.
const WORKER_DIR = path.dirname(fileURLToPath(import.meta.url));

function loadEnvFile(): void {
  const envPath = path.join(WORKER_DIR, ".env");
  if (!fs.existsSync(envPath)) return;
  // Last occurrence in the file wins (standard dotenv behavior), so an
  // appended real value beats the example line at the top. Existing
  // process.env still wins over the file.
  const fileVars = new Map<string, string>();
  for (const raw of fs.readFileSync(envPath, "utf8").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    if (!key) continue;
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    fileVars.set(key, value);
  }
  for (const [key, value] of fileVars) {
    if (process.env[key] === undefined) {
      process.env[key] = value;
    } else if (process.env[key] !== value) {
      // Shell env wins — but say so. A stale shell DATABASE_URL silently
      // pointing at another Supabase project is exactly how the worker
      // ends up writing to a DB the dashboard isn't showing.
      console.warn(`[worker] ${key} is set in the shell environment — shell value wins over pipeline-worker/.env`);
    }
  }
}

loadEnvFile();

// Credentials must be percent-encoded before anything parses this URL. A raw
// password containing @ # / : ? or a space does not fail loudly — the URL
// silently re-parses, so the connection either errors confusingly or points
// somewhere unintended. Normalise once, here, for every consumer.
if (process.env.DATABASE_URL) {
  const raw = process.env.DATABASE_URL;
  const encoded = encodePostgresCredentials(raw);
  if (encoded !== raw.trim()) {
    console.log("[worker] DATABASE_URL credentials were not percent-encoded — encoded them (@ -> %40, # -> %23, / -> %2F, : -> %3A, space -> %20)");
  }
  process.env.DATABASE_URL = encoded;
}

// Human-readable diagnosis for a bad DATABASE_URL. A raw "Invalid URL"
// from the driver tells the user nothing; this names the actual fix.
function databaseUrlProblem(value: string | undefined): string | null {
  if (!value?.trim()) return "DATABASE_URL is not set";
  if (value.includes("[") || value.includes("]")) {
    return "it contains [ or ] — the [YOUR-PASSWORD] placeholder was not replaced with the real DB password";
  }
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    return "it does not parse as a URL";
  }
  if (url.protocol !== "postgres:" && url.protocol !== "postgresql:") {
    return `it uses protocol ${url.protocol} instead of postgres:// — did you paste the https:// project URL instead of the database connection string?`;
  }
  if (!url.hostname) return "it has no host";
  return null;
}

// ------------------------------------------------- lib imports (dynamic) ----
const { analyzeAddress, parseAddressList, RpcUnavailableError, getRpcsForChain, fetchBytecodeRpc } = await import(
  "../src/lib/audit/address-fetcher.ts",
);
const { detectProxyArchitecture } = await import("../src/lib/audit/proxy-resolver.ts");
const { probeContractInterfaces } = await import("../src/lib/audit/simulator.ts");
const { withRetry } = await import("../src/lib/audit/rate-limit.ts");
const { secondPass } = await import("../src/lib/audit/persist.server.ts");
const { newLlmHealth, recordLlm, llmVerdict } = await import("./llm-health.ts");
const { implementationItems, dedupeKey } = await import("./proxy-follow.ts");
const { applyShard, parseShard } = await import("./shard.ts");
const { codeHashOf, findSiblingScan } = await import("../src/lib/audit/code-reuse.server.ts");
const { writeAuditBatch } = await import("../src/lib/audit/bulk-persist.server.ts");
const { serializedBytes } = await import("../src/lib/audit/batch-writer.ts");
const { getSql, getDbConnectionState } = await import("../src/lib/db.ts");
const { createOnDemandFourbyteLookup, fourbyteResultsFromReport } = await import("../src/lib/audit/fourbyte.ts");
// Deep Agent loop (pipeline-worker/deep-agent.ts) — same propose ->
// fork-PoC -> reward -> deeper loop as the workbench, gated to flagged
// addresses. Loaded after .env so OPENROUTER_API_KEY is visible.
const {
  runWorkerDeepAgent,
  isDeepAgentFlagged,
  applyConfirmedFindings,
  WORKER_DEEP_AGENT_DEFAULT_BACKEND_URL,
  WORKER_DEEP_AGENT_DEFAULT_MAX_ITEMS,
  WORKER_DEEP_AGENT_DEFAULT_MIN_SEVERITY,
  WORKER_DEEP_AGENT_MAX_ROUNDS,
} = await import("./deep-agent.ts");
// ResNet1D screening (Node runner) — injected into analyzeAddress so every
// pipeline entry is screened over its runtime bytecode during the audit
// and the stored risk score carries the bounded ML term. Fail-soft: when
// the model files are unavailable the runner resolves null and entries
// are stored exactly as before (see src/lib/audit/resnet-result.ts).
const { runResnetNode } = await import("../src/lib/image-ml/resnet-node.server.ts");
// Auto-PoC (pipeline-worker/auto-poc.ts) — the adjudication chain run
// automatically for eligible high/critical findings after an entry is
// persisted: LLM-gen -> Foundry backend -> verdict saved to Supabase.
// Loaded after .env like everything else (its persist deps read
// DATABASE_URL / OPENROUTER_API_KEY at call time).
const {
  runAutoPocForEntry,
  selectAutoPocFindings,
  newAutoPocRunState,
} = await import("./auto-poc.ts");

// ------------------------------------------------------------------ config --
/**
 * Behaviours this build has, reported by /status.
 *
 * Every one of these changed observable behaviour, and each time the first
 * question was "is the running process actually this code?" — answered by
 * inferring from row counts. A missing entry here means the process predates it:
 * restart before concluding anything from the numbers.
 */
const FEATURES = [
  "fourbyte-negative-cache", // bd8ea97: misses are cached, timeout 2s
  "proxy-follow", // a2768a0: implementations are queued
  "shard", // 34ded8e: shard=N/M
  "sourcify-v2", // 9dbca33: v2 endpoint (v1 was turned off 2026-07-07)
  "llm-health", // d0b5b6b: /health/llm
  "no-autopoc-cap", // af94627
] as const;

const PORT = Number.parseInt(process.env.PORT ?? "8788", 10) || 8788;
const HOST = "127.0.0.1";
const FLUSH_MAX_RECORDS = 50; // writeAuditBatch cap
const FLUSH_MAX_BYTES = 1_400_000; // writeAuditBatch caps at 1.5MB — headroom
const FLUSH_MAX_AGE_MS = 30_000;

// Memory watchdog. A 43k-address run died with "Reached heap limit Allocation
// failed" after ~3 hours (2026-10-21) with nothing logged about the trend, so a
// multi-day run could only fail blind. Now the heap is reported periodically and
// the run PARKS (resumable) before it would crash: on /start the worker skips
// already-saved rows, so parking costs nothing but a restart.
const MEMORY_CHECK_EVERY = 50;
const MEMORY_PARK_PCT = 85;
const MAX_BODY = 1024 * 1024; // bytes

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// ------------------------------------------------------------------- state --
type RunState = "idle" | "running" | "paused" | "stopping";

type Status = {
  state: RunState;
  total: number;
  completed: number;
  failed: number;
  skipped: number;
  /** Skipped mid-run by the in-run dedupe (twin in the file, or saved concurrently after /start). Included in `skipped`. */
  skippedDupes: number;
  /** Saved by an older analyzer — re-analyzed on this run. */
  stale: number;
  /** Freshness policy for this run: stale (default) | all | none. */
  refresh: string;
  /** "2/4" when this process owns one shard of the list, null otherwise. */
  shard: string | null;
  current: string | null;
  startedAt: string | null;
  lastFlushAt: string | null;
  lastError: string | null;
  addressesFile: string | null;
  chainId: string;
  aiSecondPass: boolean;
  delayMs: number;
  pending: number;
  deepAgent: boolean;
  deepAgentMaxItems: number;
  deepAgentMinSeverity: string;
  deepAgentRuns: number;
  deepAgentConfirmed: number;
  deepAgentBackendDown: boolean;
  autoPoc: boolean;
  autoPocAttempted: number;
  autoPocPassed: number;
  autoPocFailed: number;
  autoPocErrors: number;
  autoPocSkipped: number;
  autoPocShared: number;
  autoPocBackendDown: boolean;
  /** LLM health for this run — see pipeline-worker/llm-health.ts. */
  llm: ReturnType<typeof newLlmHealth>;
  llmVerdict: ReturnType<typeof llmVerdict>;
};

// One health object, shared by the tally and the verdict derived from it. Both were
// declared required on `Status` but missing from this literal, and pipeline-worker/ was
// not in tsconfig's include, so nothing caught it. At runtime the second pass read
// `status.llmVerdict.state` on undefined, the catch handler then called
// `recordLlm(status.llm, ...)` which threw `reading 'calls'`, and that throw escaped the
// catch and parked the run.
const initialLlmHealth = newLlmHealth();

let status: Status = {
  state: "idle",
  llm: initialLlmHealth,
  llmVerdict: llmVerdict(initialLlmHealth),
  total: 0,
  completed: 0,
  failed: 0,
  skipped: 0,
  skippedDupes: 0,
  stale: 0,
  refresh: "stale",
  shard: null,
  current: null,
  startedAt: null,
  lastFlushAt: null,
  lastError: null,
  addressesFile: null,
  chainId: "ethereum",
  aiSecondPass: false,
  delayMs: 600,
  pending: 0,
  deepAgent: false,
  deepAgentMaxItems: WORKER_DEEP_AGENT_DEFAULT_MAX_ITEMS,
  deepAgentMinSeverity: WORKER_DEEP_AGENT_DEFAULT_MIN_SEVERITY,
  deepAgentRuns: 0,
  deepAgentConfirmed: 0,
  deepAgentBackendDown: false,
  autoPoc: true,
  autoPocAttempted: 0,
  autoPocPassed: 0,
  autoPocFailed: 0,
  autoPocErrors: 0,
  autoPocSkipped: 0,
  autoPocShared: 0,
  autoPocBackendDown: false,
};

let runCtx: { items: BatchItem[]; index: number } | null = null;
let runPromise: Promise<void> | null = null;
// In-run dedupe: (chain, address) keys that have completed (saved or
// skipped) during THIS run. The /start skip check cannot see a twin
// later in the same file (nothing is saved yet when it runs, and saves
// flush in batches), so the loop tracks what it has already done.
// Cleared on every /start; survives pause/resume with runCtx.
const runSeen = new Set<string>();
// Auto-PoC per-run state (tally + breaker bookkeeping). Owned here
// because the /status counters read it; reset on every /start.
let autoPocState = newAutoPocRunState();
let pauseRequested = false;
let stopRequested = false;
const pending: ComprehensiveRecordInput[] = [];
// Running total of the serialized size of `pending`. Maintained incrementally
// so the pre-push size check does not re-serialize the whole batch per item.
let pendingBytes = 0;
let pendingSince: number | null = null;
let shuttingDown = false;

/** Node's old-space limit, so the watchdog can express pressure as a percentage. */
function heapLimitMb(): number {
  try {
    return Math.round(v8.getHeapStatistics().heap_size_limit / 1024 / 1024);
  } catch {
    return 0;
  }
}

function writeStatusFile(): void {
  try {
    const tmp = path.join(WORKER_DIR, "status.json.tmp");
    fs.writeFileSync(tmp, JSON.stringify({ ...status, pending: pending.length }, null, 2));
    fs.renameSync(tmp, path.join(WORKER_DIR, "status.json"));
  } catch {
    // status.json is best-effort diagnostics, never a reason to fail a run
  }
}

// ------------------------------------------------------------------ flush ---
// Serialized: flushes never overlap. The returned promise carries the real
// result (rejection = batch still queued for the next flush).
let flushChain: Promise<void> = Promise.resolve();

function flush(): Promise<void> {
  const next = flushChain.then(doFlush, doFlush);
  flushChain = next.catch(() => undefined);
  return next;
}

async function doFlush(): Promise<void> {
  if (pending.length === 0) return;
  const batch = pending.splice(0, pending.length);
  const batchBytes = pendingBytes;
  pendingBytes = 0;
  pendingSince = null;
  try {
    const sql = await getSql();
    await withRetry(() => writeAuditBatch(sql, batch), {
      retries: 3,
      baseDelayMs: 2000,
      retryOn: () => true,
    });
    status.lastFlushAt = new Date().toISOString();
    console.log(`[worker] flushed ${batch.length} records to Supabase`);
  } catch (err) {
    // Re-queue at the front so the next flush retries the same records.
    pending.unshift(...batch);
    pendingBytes += batchBytes;
    pendingSince = Date.now();
    status.lastError = `flush failed: ${err instanceof Error ? err.message : String(err)}`;
    throw err;
  } finally {
    writeStatusFile();
  }
}

// Max-age flush: a half-full batch still lands within 30s of its first record.
setInterval(() => {
  if (pending.length > 0 && pendingSince !== null && Date.now() - pendingSince > FLUSH_MAX_AGE_MS) {
    void flush().catch(() => undefined);
  }
}, 10_000).unref();

// -------------------------------------------------------------------- loop --
async function runLoop(): Promise<void> {
  const ctx = runCtx;
  if (!ctx) return;
  // 4byte resolution for this run (one on-demand lookup, reused per
  // item): cache tables first, live 4byte.directory pulls for misses.
  // A getSql failure here is logged, NOT silent: since the no-fallback
  // rework getSql throws when the configured DB is unreachable, and the
  // run itself cannot save anything in that state — every flush fails
  // and parks the run with the error in /status. The cache-less lookup
  // below is an ENRICHMENT degradation only (live API pulls, no cache
  // reads/writes): it is not a substitute store — no scan data is read
  // from or written to any local database, because there isn't one.
  let fourbyte: Awaited<ReturnType<typeof createOnDemandFourbyteLookup>> | undefined;
  try {
    fourbyte = createOnDemandFourbyteLookup(await getSql());
  } catch (err) {
    console.warn(
      `[worker] 4byte cache unavailable (DB unreachable): ${err instanceof Error ? err.message : String(err)} — continuing cache-less; saves will fail until the DB is back`,
    );
    fourbyte = createOnDemandFourbyteLookup(null);
  }
  // In-run dedupe re-checks use this handle; null (DB unreachable at
  // loop start) disables the re-check for the run — fail-open, the
  // seen-set still applies. Logged for the same reason as above.
  // Every (chain, address) the queue already holds, so a proxy implementation
  // discovered mid-run is not queued twice and a clone is not re-queued.
  const queuedKeys = new Set(ctx.items.map((i) => dedupeKey(i.chainId, i.address)));
  /** Items whose body came from an earlier scan of identical code. */
  let reusedFrom = 0;
  let dedupeSql: Awaited<ReturnType<typeof getSql>> | null = null;
  try {
    dedupeSql = await getSql();
  } catch (err) {
    console.warn(
      `[worker] in-run dedupe re-check disabled (DB unreachable): ${err instanceof Error ? err.message : String(err)}`,
    );
    dedupeSql = null;
  }
  try {
    while (ctx.index < ctx.items.length) {
      if (stopRequested || pauseRequested) break;
      const item = ctx.items[ctx.index]!;
      if (item.status === "skipped") {
        ctx.index++;
        continue;
      }
      // In-run dedupe — the two holes the /start check cannot close:
      // (a) the same (chain, address) twice in one file: the start check
      //     ran before anything was saved, and saves flush in batches,
      //     so the first copy is not in the DB when its twin is reached;
      // (b) a row saved concurrently after /start (e.g. the browser
      //     pipeline writing to the same tables mid-run).
      // Skipped items settle exactly like start-time skips (status
      // "skipped", counted, index advanced), so a resume never
      // resurrects them. Fail-open throughout: shouldSkipInRun never
      // throws, and a failed item is NOT added to the seen set, so a
      // later twin still gets its own attempt.
      const itemKey = `${item.chainId}:${item.address.toLowerCase()}`;
      if (runSeen.has(itemKey)) {
        item.status = "skipped";
        status.skipped++;
        status.skippedDupes++;
        console.log(`[worker] skipping ${item.address}: already processed in this run (duplicate in file)`);
        ctx.index++;
        writeStatusFile();
        continue;
      }
      if (dedupeSql && status.refresh !== "all") {
        if (await shouldSkipInRun(dedupeSql, item, status.refresh)) {
          runSeen.add(itemKey);
          item.status = "skipped";
          status.skipped++;
          status.skippedDupes++;
          console.log(`[worker] skipping ${item.address}: saved after this run started`);
          ctx.index++;
          writeStatusFile();
          continue;
        }
      }
      status.current = item.address;
      // The scan id is stable per item across pause/resume: if a flush
      // fails after this item's record was queued (the auto-PoC flush —
      // the one flush that runs with the current record already in
      // `pending`), the run parks with the item un-advanced, and the
      // resumed attempt re-queues a record for the same item. Reusing
      // the id makes that second queue an upsert of the same dossier
      // (writeAuditBatch keys on conflict (id)) instead of a duplicate
      // scan row for one address. A fresh /start builds fresh items, so
      // ids never leak across runs.
      const scanId = item.scanId ?? randomUUID();
      item.scanId = scanId;

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

      // Identical runtime code is analysed once (2026-10-28). The archive measured
      // 1595 scans over 375 distinct bodies — 4.25 copies each, one body accounting
      // for 341 of them. One eth_getCode plus a hash lookup decides whether the
      // registry fetch and the source analysis can be skipped; the value, ABI and
      // probes still run, because those describe THIS deployment.
      //
      // Fail-open throughout: any problem here degrades to the normal path, never
      // to a skipped or failed item.
      let bodyOverride: { body: string; inputKind: "source" | "bytecode" } | undefined;
      if (dedupeSql) {
        try {
          const code = await fetchBytecodeRpc(item.address, getRpcsForChain(item.chainId));
          const hash = codeHashOf(code);
          if (hash) {
            const sibling = await findSiblingScan(dedupeSql, item.chainId, hash, item.address);
            if (sibling?.body) {
              bodyOverride = {
                body: sibling.body,
                inputKind: /^0x[0-9a-fA-F]+$/.test(sibling.body.trim()) ? "bytecode" : "source",
              };
            }
          }
        } catch {
          // no dedupe for this item; the normal path is unchanged
        }
      }

      // Analyze with retries: every queued address is a contract, so a
      // failure here is a transient provider hiccup, not a dead address.
      let result: Awaited<ReturnType<typeof analyzeAddress>>;
      try {
        result = await withRetry(
          () =>
            analyzeAddress(item.address, item.chainId, item.label, {
              fourbyte,
              resnetRunner: runResnetNode,
              ...(bodyOverride ? { bodyOverride } : {}),
            }),
          {
            retries: 2,
            baseDelayMs: 2000,
            retryOn: () => true,
          },
        );
      } catch (err) {
        // RPC outage: park the run as paused instead of failing the item.
        // The item stays at the current index, so resume retries it.
        // Marking outage items failed would burn the whole queue on a
        // transient provider failure (exactly what happened 2026-10-16
        // when both default RPCs were down).
        if (err instanceof RpcUnavailableError) {
          status.lastError = `${item.address}: ${err.message} — run parked, resume retries this item`;
          console.warn("[worker] run parked (RPC outage):", status.lastError);
          pauseRequested = true;
          writeStatusFile();
          break;
        }
        status.failed++;
        status.lastError = `${item.address}: ${err instanceof Error ? err.message : String(err)}`;
        ctx.index++;
        writeStatusFile();
        if (status.delayMs > 0) await sleep(status.delayMs);
        continue;
      }

      const [proxyOutcome, probeOutcome] = await Promise.all([proxyPromise, probePromise]);
      const proxyInfo = proxyOutcome.status === "fulfilled" ? proxyOutcome.value : null;

      // Follow the proxy: an implementation's logic is where a finding can be,
      // and analysing the delegatecall shell instead is the pipeline's largest
      // silent blind spot. Each implementation becomes its own queue entry with
      // its own source, findings and version stamp; the proxy's record keeps the
      // link through proxy_info_json.
      const followed = implementationItems(proxyInfo, item.chainId, queuedKeys);
      if (followed.length > 0) {
        for (const impl of followed) {
          queuedKeys.add(dedupeKey(impl.chainId, impl.address));
          ctx.items.push(impl as never);
        }
        status.total = ctx.items.length;
        console.log(
          `[worker] ${item.address} is a proxy — queued ${followed.length} implementation(s): ${followed
            .map((f) => f.address)
            .join(", ")}`,
        );
        writeStatusFile();
      }
      const probes = probeOutcome.status === "fulfilled" ? probeOutcome.value : [];

      // Opt-in OpenRouter second pass, per item (keeps the bulk save fast).
      // Never fails the item. No key -> secondPass returns unavailable.
      if (status.aiSecondPass) {
        try {
          const pass = await secondPass(result.report, result.rawBody);
          if (pass.text) result.report.aiNarrative = pass.text;
          result.report.aiStatus = pass.status;
          // `ok` with no text is the quiet failure: a 200 the output contract
          // rejected looks like success in a log and leaves a fallback
          // narrative behind. Count it as `empty`, not `ok`.
          const before = status.llmVerdict.state;
          recordLlm(
            status.llm,
            pass.status === "unavailable" ? "unavailable" : pass.text ? "ok" : "empty",
            pass.text ? undefined : `status=${pass.status}, no usable text`,
          );
          status.llmVerdict = llmVerdict(status.llm);
          if (status.llmVerdict.state !== before && status.llmVerdict.state !== "smooth") {
            console.warn(`[worker] LLM ${status.llmVerdict.state}: ${status.llmVerdict.reason}`);
          }
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.warn("[worker] second pass notice:", msg);
          recordLlm(status.llm, "error", msg);
          status.llmVerdict = llmVerdict(status.llm);
        }
      }

      // Deep Agent (agentic exploit search) for flagged addresses only.
      // Never fails the item: the loop catches its own errors and the
      // static-only record stands if the agent finds nothing or the
      // backend is down. A paused/stopped run waits for the current
      // item — including an in-flight agent loop — to finish first.
      const capHit =
        status.deepAgentMaxItems > 0 && status.deepAgentRuns >= status.deepAgentMaxItems;
      if (status.deepAgent && !status.deepAgentBackendDown && !capHit) {
        if (isDeepAgentFlagged(result.report, status.deepAgentMinSeverity as "critical" | "high" | "medium")) {
          try {
            const da = await runWorkerDeepAgent(
              { chainId: item.chainId,
                address: item.address,
                contractName: result.report.label,
                body: result.rawBody,
                findings: result.report.findings,
                inputKind: result.report.inputKind,
                fourbyte: fourbyteResultsFromReport(result.report),
              },
              {
                backendUrl:
                  process.env.FOUNDRY_BACKEND_URL?.trim() || WORKER_DEEP_AGENT_DEFAULT_BACKEND_URL,
                maxRounds: WORKER_DEEP_AGENT_MAX_ROUNDS,
                minSeverity: status.deepAgentMinSeverity as "critical" | "high" | "medium",
              },
            );
            if (da.ran) {
              status.deepAgentRuns++;
              status.deepAgentConfirmed += da.confirmed.length;
              applyConfirmedFindings(result.report, da.confirmed, da.note);
              if (status.deepAgentMaxItems > 0 && status.deepAgentRuns >= status.deepAgentMaxItems) {
                console.log(`[worker] deep agent item cap reached (${status.deepAgentMaxItems}) — remaining flagged addresses keep static-only records`);
              }
            }
            if (da.backendDown) {
              // Circuit breaker: the PoC backend is down. Stop spending
              // LLM calls on agent rounds for the rest of this run — the
              // static pipeline keeps going. Restart the backend and
              // start a new run (skip-check resumes past saved rows) to
              // re-enable the agent.
              status.deepAgentBackendDown = true;
              console.warn("[worker] deep agent disabled for the rest of this run: PoC backend unreachable");
            }
            console.log(`[worker] deep agent ${item.address}: ${da.note}${da.skipReason ? ` (skipped: ${da.skipReason})` : ""}`);
          } catch (err) {
            console.warn("[worker] deep agent notice:", err instanceof Error ? err.message : String(err));
          }
        }
      }

      const record: ComprehensiveRecordInput = {
        id: scanId,
        label: item.label,
        report: result.report,
        body: result.rawBody,
        targetAddress: item.address,
        chainId: item.chainId,
        compilerVersion: result.report.inventory.compiler,
        sourceOrigin: "pipeline",
        indexToRag: true,
        proxyInfo,
        probes,
      };

      // Byte-aware batching: writeAuditBatch caps at 50 records / 1.5MB.
      // Flush BEFORE pushing so a flush failure leaves this item un-advanced
      // (it is re-analyzed on resume — wasteful but never lost).
      const recordBytes = serializedBytes(record);
      if (pending.length >= FLUSH_MAX_RECORDS) await flush();
      else if (pending.length > 0 && pendingBytes + recordBytes > FLUSH_MAX_BYTES) await flush();
      pending.push(record);
      pendingBytes += recordBytes;
      if (pendingSince === null) pendingSince = Date.now();

      // Auto-PoC: this entry's initial scores include a high/critical
      // finding, so run the adjudication chain (LLM-gen -> Foundry ->
      // save) for each eligible one now instead of waiting for a human
      // on the PoC Audits page. The chain's save UPDATES the finding
      // rows, so the record must be persisted first: flush (a flush
      // failure parks the run with the item un-advanced, exactly like
      // any other flush failure). Never fails the item — the module
      // catches its own errors and the static record already landed.
      // A paused/stopped run waits for the in-flight chain, same as
      // the Deep Agent loop above.
      if (
        status.autoPoc &&
        !autoPocState.breakerTripped &&
        selectAutoPocFindings(result.report, result.rawBody).length > 0
      ) {
        // Flush before spending backend time: the static record for every
        // entry so far is durable before a slow PoC run starts.
        await flush();
        const ap = await runAutoPocForEntry(
          autoPocState,
          {
            scanId,
            address: item.address,
            chainId: item.chainId,
            report: result.report,
            body: result.rawBody,
          },
          {
            backendUrl:
              process.env.FOUNDRY_BACKEND_URL?.trim() || WORKER_DEEP_AGENT_DEFAULT_BACKEND_URL,
            enabled: status.autoPoc,
          },
        );
        status.autoPocAttempted = autoPocState.tally.attempted;
        status.autoPocPassed = autoPocState.tally.passed;
        status.autoPocFailed = autoPocState.tally.failed;
        status.autoPocErrors = autoPocState.tally.errors;
        status.autoPocSkipped = autoPocState.tally.skipped;
        status.autoPocShared = autoPocState.tally.shared;
        status.autoPocBackendDown = autoPocState.breakerTripped;
        console.log(`[worker] auto-poc ${item.address}: ${ap.note}`);
      }

      item.status = "completed";
      runSeen.add(itemKey);
      status.completed++;
      if (bodyOverride) reusedFrom++;
      ctx.index++;
      if (status.completed % 100 === 0) {
        console.log(
          `[worker] ${status.completed}/${status.total} completed (${status.failed} failed, ${status.skipped} skipped)`,
        );
      }
      if (status.completed % MEMORY_CHECK_EVERY === 0) {
        const mu = process.memoryUsage();
        const limitMb = heapLimitMb();
        const heapMb = Math.round(mu.heapUsed / 1024 / 1024);
        const pct = limitMb > 0 ? Math.round((heapMb / limitMb) * 100) : 0;
        const vc = valueCacheStats();
        console.log(
          `[worker] memory: heap ${heapMb}MB / ~${limitMb}MB (${pct}%), rss ${Math.round(mu.rss / 1024 / 1024)}MB, valuation cache ${vc.entries} entries / ${Math.round(vc.bytes / 1024)}KB`,
        );
        if (limitMb > 0 && pct >= MEMORY_PARK_PCT) {
          // Flush what we have, then park: resume skips the saved rows.
          await flush();
          status.lastError =
            `memory pressure: heap ${heapMb}MB of ~${limitMb}MB (${pct}%) — run parked so it resumes instead of crashing. Restart with a larger WORKER_MAX_OLD_SPACE_MB if this recurs.`;
          console.warn("[worker]", status.lastError);
          pauseRequested = true;
          writeStatusFile();
          break;
        }
      }
      writeStatusFile();
      if (status.delayMs > 0 && ctx.index < ctx.items.length) await sleep(status.delayMs);
    }
    await flush();
  } catch (err) {
    // Flush failure (or an unexpected loop error): park the run as paused
    // with context kept, so resume retries after the DB is back.
    status.lastError = err instanceof Error ? err.message : String(err);
    console.warn("[worker] run parked:", status.lastError);
    pauseRequested = true;
  } finally {
    status.current = null;
    if (stopRequested) {
      runCtx = null;
      status.state = "idle";
    } else if (pauseRequested) {
      status.state = "paused";
    } else {
      runCtx = null;
      status.state = "idle";
      console.log(
        `[worker] run finished: ${status.completed} completed, ${status.failed} failed, ${status.skipped} skipped (${status.skippedDupes} in-run duplicates, ${reusedFrom} reused an earlier scan of identical code)`,
      );
    }
    pauseRequested = false;
    stopRequested = false;
    writeStatusFile();
  }
}

// -------------------------------------------------------------------- http --
function sendJson(res: http.ServerResponse, statusCode: number, obj: unknown): void {
  res.writeHead(statusCode, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}

function readJsonBody(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let bytes = 0;
    let tooBig = false;
    req.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > MAX_BODY) {
        tooBig = true;
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (tooBig) {
        reject(new Error("request body exceeds 1MB cap"));
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
      } catch {
        reject(new Error("body must be valid JSON"));
      }
    });
    req.on("error", reject);
  });
}

async function handleStart(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  if (status.state !== "idle") {
    sendJson(res, 409, { error: `a run is already ${status.state} — pause or stop it first` });
    return;
  }
  // Claim the run SYNCHRONOUSLY, before any await.
  //
  // Measured 2026-10-28: two /start calls a few seconds apart both announced
  // "started:", which the guard above should have prevented. handleStart is invoked
  // as `void handleStart(...)`, and it awaits readJsonBody and the address-list read
  // before the loop starts and before `status.state` is set to "running" — so two
  // requests could both pass the idle check. Two live run loops then share `runCtx`,
  // `runSeen`, the batch buffer and the auto-PoC state, and the second run's item list
  // silently replaces the first one's mid-flight.
  //
  // Setting the state here, with no await between the check and the assignment, makes
  // the claim atomic under Node's single thread. Every early return below puts it back.
  status.state = "running";
  writeStatusFile();
  let body: Record<string, unknown>;
  try {
    body = (await readJsonBody(req)) as Record<string, unknown>;
  } catch (err) {
    status.state = "idle";
    writeStatusFile();
    sendJson(res, 400, { error: err instanceof Error ? err.message : String(err) });
    return;
  }
  const refresh = (() => {
    const raw = typeof body.refresh === "string" ? body.refresh.trim().toLowerCase() : "";
    return raw === "all" || raw === "none" ? raw : "stale";
  })();
  const addressesFile = typeof body.addressesFile === "string" ? body.addressesFile.trim() : "";
  if (!addressesFile) {
    status.state = "idle";
    writeStatusFile();
    sendJson(res, 400, { error: "addressesFile is required (path on this machine, e.g. ~/addresses.csv)" });
    return;
  }
  // Fail fast: the worker must never silently fall back to db.ts's bundled
  // default Supabase config and write a multi-day run to the wrong database.
  // Validate the shape first so a bad value fails with a fixable message
  // instead of the driver's opaque "Invalid URL" from the skip check.
  const dbProblem = databaseUrlProblem(process.env.DATABASE_URL);
  if (dbProblem) {
    status.state = "idle";
    writeStatusFile();
    sendJson(res, 400, {
      error: `DATABASE_URL in pipeline-worker/.env is not a valid Supabase pooler URL: ${dbProblem}. Fix: use the Connection string → URI (pooler mode, port 6543) from Supabase Settings → Database, keep exactly one DATABASE_URL line. (Credentials are percent-encoded automatically — @ # / : ? and spaces in the password are handled, so do not pre-encode them by hand.)`,
    });
    status.state = "idle";
    writeStatusFile();
    return;
  }
  const chainId = typeof body.chainId === "string" && body.chainId.trim() ? body.chainId.trim() : "ethereum";
  const aiSecondPass = body.aiSecondPass === true;
  // Deep Agent: agentic exploit search for flagged addresses (see
  // pipeline-worker/deep-agent.ts). Same OpenRouter key requirement as
  // aiSecondPass — the agent loop is LLM-driven.
  const deepAgent = body.deepAgent === true;
  if ((aiSecondPass || deepAgent) && !process.env.OPENROUTER_API_KEY?.trim()) {
    status.state = "idle";
    writeStatusFile();
    sendJson(res, 400, { error: "aiSecondPass / deepAgent needs OPENROUTER_API_KEY in pipeline-worker/.env" });
    status.state = "idle";
    writeStatusFile();
    return;
  }
  // Budget guard: each flagged address costs up to 3 LLM calls + up to 6
  // fork PoCs. 0 = unlimited (not recommended on a 43k run).
  const deepAgentMaxItems =
    typeof body.deepAgentMaxItems === "number" && Number.isFinite(body.deepAgentMaxItems) && body.deepAgentMaxItems >= 0
      ? Math.floor(body.deepAgentMaxItems)
      : WORKER_DEEP_AGENT_DEFAULT_MAX_ITEMS;
  const deepAgentMinSeverity =
    body.deepAgentMinSeverity === "critical" || body.deepAgentMinSeverity === "medium"
      ? body.deepAgentMinSeverity
      : WORKER_DEEP_AGENT_DEFAULT_MIN_SEVERITY;
  const delayMs =
    typeof body.delayMs === "number" && Number.isFinite(body.delayMs) && body.delayMs >= 0
      ? Math.floor(body.delayMs)
      : 600;
  // Auto-PoC: ON unless explicitly disabled (autoPoc: false). No
  // OpenRouter key requirement at start — without a key the chain's
  // generation/repair attempts return nothing and outcomes save
  // honestly (template/snippet PoCs still run); aiSecondPass and
  // deepAgent keep their hard requirement above.
  const autoPoc = body.autoPoc !== false;
  let text: string;
  try {
    text = await fsp.readFile(addressesFile, "utf8");
  } catch {
    status.state = "idle";
    writeStatusFile();
    sendJson(res, 400, { error: `cannot read addresses file: ${addressesFile}` });
    status.state = "idle";
    writeStatusFile();
    return;
  }
  // Sharding: N processes, one flag each, disjoint by hash of address. Parsed
  // before the skip check so each shard only skips what it would have analysed.
  let shard: { index: number; of: number } | null = null;
  try {
    shard = parseShard(body.shard);
  } catch (err) {
    status.state = "idle";
    writeStatusFile();
    sendJson(res, 400, { error: err instanceof Error ? err.message : String(err) });
    status.state = "idle";
    writeStatusFile();
    return;
  }
  const allItems = parseAddressList(text, chainId);
  const items = applyShard(allItems, shard);
  if (items.length === 0) {
    status.state = "idle";
    writeStatusFile();
    sendJson(res, 400, { error: "no valid addresses in file" });
    status.state = "idle";
    writeStatusFile();
    return;
  }

  // Skip/resume: already-saved (chain, address) pairs, same semantics as
  // the browser's handleResumeSupabase. A failed skip check aborts the
  // start — re-analyzing everything blind would waste a multi-day run.
  // Skip what the CURRENT analyzer already saved; re-analyze what an older one
  // saved. Records written before the stamp existed (analyzer_version IS NULL)
  // are stale, so the first run after a pipeline change refreshes the archive
  // instead of skipping it — which is the whole point of the stamp.
  //   refresh=stale (default) — skip current, re-analyze stale
  //   refresh=all             — re-analyze everything in the file
  //   refresh=none            — any saved row counts as done (current AND stale
  //                             skipped): use when you want the NEW addresses in
  //                             a file and are not ready to pay for a re-analysis
  //                             of rows an older analyzer already wrote
  // Stage logging. The 2026-10-31 OOM died 35 s in with nothing but a V8 trace, and
  // "which stage" cost three rounds of inference. These lines are cheap and answer it
  // directly next time: rss/heap per stage, and the queue size.
  const mem = (): string => {
    const m = process.memoryUsage();
    return `heap ${Math.round(m.heapUsed / 1048576)}MB rss ${Math.round(m.rss / 1048576)}MB`;
  };
  console.log(`[mem] start: ${items.length} items, ${mem()}`);
  let skipped = 0;
  let stale = 0;
  try {
    // Migration 0014 must be applied before a run: the skip reads the stamp and
    // every save writes it. Fail with instructions, not a raw SQL error.
    await assertFreshnessSchema(await getSql());
    if (refresh !== "all") {
      const wanted = items.map((i) => ({ chainId: i.chainId, address: i.address }));
      const { current, stale: staleKeys } = await savedScanVersions(await getSql(), wanted, analyzerStamp());
      for (const item of items) {
        const key = `${item.chainId}:${item.address.toLowerCase()}`;
        const saved = current.has(key) || staleKeys.has(key);
        if (refresh === "none") {
          if (saved) { item.status = "skipped"; skipped++; }
          continue;
        }
        if (current.has(key)) { item.status = "skipped"; skipped++; }
        else if (staleKeys.has(key)) stale++;
      }
    }
  } catch (err) {
    sendJson(res, 500, {
      error: `could not check Supabase for already-saved addresses: ${err instanceof Error ? err.message : String(err)}`,
    });
    status.state = "idle";
    writeStatusFile();
    return;
  }

  console.log(`[mem] classified (${skipped} current, ${stale} stale): ${mem()}`);
  status = {
    ...status,
    state: "running",
    total: items.length,
    completed: 0,
    failed: 0,
    skipped,
    skippedDupes: 0,
    stale,
    refresh,
    current: null,
    startedAt: new Date().toISOString(),
    lastFlushAt: null,
    lastError: null,
    addressesFile,
    chainId,
    aiSecondPass,
    delayMs,
    pending: 0,
    deepAgent,
    deepAgentMaxItems,
    deepAgentMinSeverity,
    deepAgentRuns: 0,
    deepAgentConfirmed: 0,
    deepAgentBackendDown: false,
    autoPoc,
    autoPocAttempted: 0,
    autoPocPassed: 0,
    autoPocFailed: 0,
    autoPocErrors: 0,
    autoPocSkipped: 0,
    autoPocBackendDown: false,
  };
  runCtx = { items, index: 0 };
  runSeen.clear();
  autoPocState = newAutoPocRunState();
  pauseRequested = false;
  stopRequested = false;
  runPromise = runLoop().catch((err) => {
    console.warn("[worker] run loop error:", err instanceof Error ? err.message : String(err));
  });
  writeStatusFile();
  console.log(
    `[worker] started: ${items.length} addresses — ${skipped} current (skipped), ${stale} stale (${refresh === "none" ? "skipped" : "re-analysing"}), ${items.length - skipped - stale} new (to analyse); refresh=${refresh}${shard ? `, shard=${shard.index}/${shard.of} of ${allItems.length}` : ""}, chain=${chainId}, ai=${aiSecondPass}, delay=${delayMs}ms, deepAgent=${deepAgent} (minSeverity=${deepAgentMinSeverity}, maxItems=${deepAgentMaxItems === 0 ? "unlimited" : deepAgentMaxItems}), autoPoc=${autoPoc} (no attempt cap)`,
  );
  sendJson(res, 200, {
    ok: true,
    started: true,
    total: items.length,
    skipped,
    stale,
    // What the run will actually analyse: everything not skipped and not stale.
    toAnalyse: items.length - skipped - (refresh === "none" ? stale : 0),
    newAddresses: items.length - skipped - stale,
    refresh,
    shard: shard ? `${shard.index}/${shard.of}` : null,
    deepAgent,
    deepAgentMaxItems,
    deepAgentMinSeverity,
    autoPoc,
  });
}

// Which database is the worker actually talking to? The dashboard-shows-0
// confusion (2026-10-16) came from not knowing this: the effective
// DATABASE_URL may come from the shell env (which wins over .env) and may
// point at a different Supabase project than the one open in the dashboard.
// /status reports the identity (host/user/database, NEVER the password)
// plus a live row count, so one glance settles "which DB" and "how many".
function describeDatabase(): { host: string; port: string; user: string; database: string } | null {
  const value = process.env.DATABASE_URL?.trim();
  if (!value) return null;
  try {
    const url = new URL(value);
    return {
      host: url.hostname,
      port: url.port,
      user: decodeURIComponent(url.username),
      database: decodeURIComponent(url.pathname.replace(/^\//, "")),
    };
  } catch {
    return null;
  }
}

async function handleStatus(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  let dbScans: number | null = null;
  let dbError: string | null = null;
  // Effective connection state from the same resolution getSql performs.
  // Since the no-fallback rework there is no local substitute: "failed"
  // means the configured DB is unreachable and NOTHING is being read from
  // or written to any other store; "unconfigured" means no DATABASE_URL.
  let dbState: "remote" | "failed" | "unconfigured" = "unconfigured";
  let dbStateError: string | null = null;
  try {
    const conn = await getDbConnectionState();
    dbState = conn.state;
    dbStateError = conn.state === "failed" ? conn.error : null;
  } catch (err) {
    dbState = "failed";
    dbStateError = err instanceof Error ? err.message : String(err);
  }
  const dbProblem = databaseUrlProblem(process.env.DATABASE_URL);
  if (dbProblem) {
    dbError = dbProblem;
  } else if (dbState === "remote") {
    try {
      const sql = await getSql();
      const rows = await sql<{ n: string }>`SELECT count(*) AS n FROM contract_scans`;
      const n = Number.parseInt(rows[0]?.n ?? "", 10);
      dbScans = Number.isFinite(n) ? n : null;
    } catch (err) {
      dbError = err instanceof Error ? err.message : String(err);
    }
  } else if (dbState === "failed") {
    // The count is unknown — null, with the failure in dbError. Reporting
    // 0 here would repeat the Records masquerade in the monitor.
    dbError = dbStateError;
  }
  sendJson(res, 200, {
    ...status,
    pending: pending.length,
    db: describeDatabase(),
    dbScans,
    dbError,
    dbState,
    dbStateError,
    features: FEATURES,
  });
}

const server = http.createServer((req, res) => {
  // Loopback-only backend; permissive CORS is fine here.
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? HOST}`);
  // A trailing slash 404s on an exact-match route table, which reads as "the
  // route does not exist" when it does. Normalise once, here.
  const route = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, "") : url.pathname;

  // How much of the archive the current analyzer would refresh. Ask this
  // before committing to a long run: a pipeline change makes every older row
  // stale, so "freshen everything" is a run with refresh=stale (the default).
  if (req.method === "GET" && route === "/freshness") {
    void getSql()
      .then((sql) => scanFreshness(sql).then((f) => sendJson(res, 200, { ...f, analyzer: analyzerStamp() })))
      .catch((err) => sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) }));
    return;
  }

  // One-line LLM health poll: `curl -s localhost:8788/health/llm`.
  // The key itself is never returned — only whether one is configured.
  if (req.method === "GET" && route === "/health/llm") {
    sendJson(res, 200, {
      verdict: status.llmVerdict,
      ...status.llm,
      model: process.env.OPENROUTER_MODEL?.trim() || "(default)",
      keyPresent: Boolean(process.env.OPENROUTER_API_KEY?.trim()),
    });
    return;
  }

  if (req.method === "GET" && route === "/status") {
    void handleStatus(req, res);
    return;
  }

  if (req.method === "POST" && route === "/start") {
    void handleStart(req, res);
    return;
  }

  if (req.method === "POST" && route === "/pause") {
    if (status.state !== "running") {
      sendJson(res, 409, { error: `no run is active (state: ${status.state})` });
      return;
    }
    pauseRequested = true;
    status.state = "stopping";
    writeStatusFile();
    sendJson(res, 200, { ok: true, state: "stopping" });
    return;
  }

  if (req.method === "POST" && route === "/resume") {
    if (status.state !== "paused" || !runCtx) {
      sendJson(res, 409, { error: `nothing to resume (state: ${status.state})` });
      return;
    }
    pauseRequested = false;
    status.state = "running";
    writeStatusFile();
    runPromise = runLoop().catch((err) => {
      console.warn("[worker] run loop error:", err instanceof Error ? err.message : String(err));
    });
    sendJson(res, 200, { ok: true, resumed: true });
    return;
  }

  if (req.method === "POST" && route === "/stop") {
    if (status.state === "paused") {
      runCtx = null;
      status.state = "idle";
      writeStatusFile();
      sendJson(res, 200, { ok: true, state: "idle" });
      return;
    }
    if (status.state === "running" || status.state === "stopping") {
      stopRequested = true;
      status.state = "stopping";
      writeStatusFile();
      sendJson(res, 200, { ok: true, state: "stopping" });
      return;
    }
    sendJson(res, 200, { ok: true, state: "idle" });
    return;
  }

  // The index: hitting the base URL should not be an error, and a mistyped path
  // should say what the routes are rather than just "not found" — the failure
  // this replaces cost a round trip to diagnose.
  const routes = {
    "GET /status": "run state, counters, LLM health",
    "GET /health/llm": "LLM verdict in one line",
    "GET /freshness": "how stale the analysed set is",
    "POST /start": "begin a run",
    "POST /pause": "pause after the current item",
    "POST /resume": "resume a paused run",
    "POST /stop": "stop after the current item",
  };
  if (req.method === "GET" && (route === "/" || route === "/health")) {
    sendJson(res, 200, { ok: true, routes });
    return;
  }
  sendJson(res, 404, { error: "not found", path: url.pathname, routes });
});

// ------------------------------------------------------- graceful shutdown --
async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) {
    console.log("[worker] second signal — exiting now");
    process.exit(1);
  }
  shuttingDown = true;
  console.log(`[worker] ${signal} — finishing current item, flushing, exiting`);
  if (status.state === "running" || status.state === "stopping") {
    stopRequested = true;
    try {
      await runPromise;
    } catch {
      // the loop handles its own errors
    }
  }
  try {
    await flush();
  } catch {
    // flush logs + re-queues in memory; records that never reached Supabase
    // are re-analyzed on the next start (the skip-check only covers saved
    // rows), so nothing is double-saved — just re-done.
  }
  writeStatusFile();
  server.close();
  process.exit(0);
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

server.listen(PORT, HOST, () => {
  console.log(`[worker] SmartKontrakt pipeline worker listening on http://${HOST}:${PORT} (loopback only)`);
  const db = describeDatabase();
  if (db) console.log(`[worker] database: ${db.user}@${db.host}:${db.port}/${db.database}`);
  // Boot probe: prove the configured connection actually works, loudly.
  // There is no local substitute to degrade to — a failed probe means
  // runs cannot start (handleStart's freshness check throws) and saves
  // cannot land; /status carries the same state for the monitor.
  void getDbConnectionState()
    .then((conn) => {
      if (conn.state === "remote") {
        console.log("[worker] database connection: OK (remote)");
      } else if (conn.state === "failed") {
        console.warn(`[worker] database connection: FAILED — ${conn.error ?? "unknown error"} No fallback is in use; fix DATABASE_URL in pipeline-worker/.env.`);
      } else {
        console.warn("[worker] database connection: NOT CONFIGURED — set DATABASE_URL in pipeline-worker/.env before starting a run.");
      }
    })
    .catch((err) => {
      console.warn(`[worker] database connection probe failed: ${err instanceof Error ? err.message : String(err)}`);
    });
  console.log(
    `[worker] DATABASE_URL ${process.env.DATABASE_URL ? "set" : "MISSING — set it in pipeline-worker/.env before starting a run"}${process.env.DATABASE_URL && databaseUrlProblem(process.env.DATABASE_URL) ? ` — WARNING: ${databaseUrlProblem(process.env.DATABASE_URL)}` : ""}`,
  );
  console.log(
    `[worker] OPENROUTER_API_KEY ${process.env.OPENROUTER_API_KEY ? "set" : "not set (AI second pass stays off unless requested)"}`,
  );
});

