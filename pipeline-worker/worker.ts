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
 *   POST /start    — { addressesFile, chainId?, aiSecondPass?, delayMs? }
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

import type { BatchItem } from "../src/lib/audit/address-fetcher.ts";
import type { ComprehensiveRecordInput } from "../src/lib/audit/persist.server.ts";

// ---------------------------------------------------------------- .env ----
// Tiny dotenv parser, no dependency. pipeline-worker/.env only; existing
// process.env wins. Must run before the lib imports below.
const WORKER_DIR = path.dirname(fileURLToPath(import.meta.url));

function loadEnvFile(): void {
  const envPath = path.join(WORKER_DIR, ".env");
  if (!fs.existsSync(envPath)) return;
  for (const raw of fs.readFileSync(envPath, "utf8").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    if (!key || process.env[key] !== undefined) continue;
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
}

loadEnvFile();

// ------------------------------------------------- lib imports (dynamic) ----
const { analyzeAddress, parseAddressList } = await import("../src/lib/audit/address-fetcher.ts");
const { detectProxyArchitecture } = await import("../src/lib/audit/proxy-resolver.ts");
const { probeContractInterfaces } = await import("../src/lib/audit/simulator.ts");
const { withRetry } = await import("../src/lib/audit/rate-limit.ts");
const { secondPass } = await import("../src/lib/audit/persist.server.ts");
const { writeAuditBatch } = await import("../src/lib/audit/bulk-persist.server.ts");
const { serializedBytes } = await import("../src/lib/audit/batch-writer.ts");
const { getSql } = await import("../src/lib/db.ts");

// ------------------------------------------------------------------ config --
const PORT = Number.parseInt(process.env.PORT ?? "8788", 10) || 8788;
const HOST = "127.0.0.1";
const FLUSH_MAX_RECORDS = 50; // writeAuditBatch cap
const FLUSH_MAX_BYTES = 1_400_000; // writeAuditBatch caps at 1.5MB — headroom
const FLUSH_MAX_AGE_MS = 30_000;
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
  current: string | null;
  startedAt: string | null;
  lastFlushAt: string | null;
  lastError: string | null;
  addressesFile: string | null;
  chainId: string;
  aiSecondPass: boolean;
  delayMs: number;
  pending: number;
};

let status: Status = {
  state: "idle",
  total: 0,
  completed: 0,
  failed: 0,
  skipped: 0,
  current: null,
  startedAt: null,
  lastFlushAt: null,
  lastError: null,
  addressesFile: null,
  chainId: "ethereum",
  aiSecondPass: false,
  delayMs: 600,
  pending: 0,
};

let runCtx: { items: BatchItem[]; index: number } | null = null;
let runPromise: Promise<void> | null = null;
let pauseRequested = false;
let stopRequested = false;
let pending: ComprehensiveRecordInput[] = [];
let pendingSince: number | null = null;
let shuttingDown = false;

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
  try {
    while (ctx.index < ctx.items.length) {
      if (stopRequested || pauseRequested) break;
      const item = ctx.items[ctx.index]!;
      if (item.status === "skipped") {
        ctx.index++;
        continue;
      }
      status.current = item.address;
      const scanId = randomUUID();

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
          retries: 2,
          baseDelayMs: 2000,
          retryOn: () => true,
        });
      } catch (err) {
        status.failed++;
        status.lastError = `${item.address}: ${err instanceof Error ? err.message : String(err)}`;
        ctx.index++;
        writeStatusFile();
        if (status.delayMs > 0) await sleep(status.delayMs);
        continue;
      }

      const [proxyOutcome, probeOutcome] = await Promise.all([proxyPromise, probePromise]);
      const proxyInfo = proxyOutcome.status === "fulfilled" ? proxyOutcome.value : null;
      const probes = probeOutcome.status === "fulfilled" ? probeOutcome.value : [];

      // Opt-in OpenRouter second pass, per item (keeps the bulk save fast).
      // Never fails the item. No key -> secondPass returns unavailable.
      if (status.aiSecondPass) {
        try {
          const pass = await secondPass(result.report, result.rawBody);
          if (pass.text) result.report.aiNarrative = pass.text;
          result.report.aiStatus = pass.status;
        } catch (err) {
          console.warn("[worker] second pass notice:", err instanceof Error ? err.message : String(err));
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
      if (pending.length >= FLUSH_MAX_RECORDS) await flush();
      else if (pending.length > 0 && serializedBytes([...pending, record]) > FLUSH_MAX_BYTES) await flush();
      pending.push(record);
      if (pendingSince === null) pendingSince = Date.now();

      item.status = "completed";
      status.completed++;
      ctx.index++;
      if (status.completed % 100 === 0) {
        console.log(
          `[worker] ${status.completed}/${status.total} completed (${status.failed} failed, ${status.skipped} skipped)`,
        );
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
        `[worker] run finished: ${status.completed} completed, ${status.failed} failed, ${status.skipped} skipped`,
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
  let body: Record<string, unknown>;
  try {
    body = (await readJsonBody(req)) as Record<string, unknown>;
  } catch (err) {
    sendJson(res, 400, { error: err instanceof Error ? err.message : String(err) });
    return;
  }
  const addressesFile = typeof body.addressesFile === "string" ? body.addressesFile.trim() : "";
  if (!addressesFile) {
    sendJson(res, 400, { error: "addressesFile is required (path on this machine, e.g. ~/addresses.csv)" });
    return;
  }
  // Fail fast: the worker must never silently fall back to db.ts's bundled
  // default Supabase config and write a multi-day run to the wrong database.
  if (!process.env.DATABASE_URL?.trim()) {
    sendJson(res, 400, {
      error: "DATABASE_URL is required in pipeline-worker/.env (Supabase pooler URL, port 6543) — see pipeline-worker/README.md",
    });
    return;
  }
  const chainId = typeof body.chainId === "string" && body.chainId.trim() ? body.chainId.trim() : "ethereum";
  const aiSecondPass = body.aiSecondPass === true;
  if (aiSecondPass && !process.env.OPENROUTER_API_KEY?.trim()) {
    sendJson(res, 400, { error: "aiSecondPass needs OPENROUTER_API_KEY in pipeline-worker/.env" });
    return;
  }
  const delayMs =
    typeof body.delayMs === "number" && Number.isFinite(body.delayMs) && body.delayMs >= 0
      ? Math.floor(body.delayMs)
      : 600;

  let text: string;
  try {
    text = await fsp.readFile(addressesFile, "utf8");
  } catch {
    sendJson(res, 400, { error: `cannot read addresses file: ${addressesFile}` });
    return;
  }
  const items = parseAddressList(text, chainId);
  if (items.length === 0) {
    sendJson(res, 400, { error: "no valid addresses in file" });
    return;
  }

  // Skip/resume: already-saved (chain, address) pairs, same semantics as
  // the browser's handleResumeSupabase. A failed skip check aborts the
  // start — re-analyzing everything blind would waste a multi-day run.
  let skipped = 0;
  try {
    const sql = await getSql();
    const rows = await sql<{ chain_id: string; addr: string }>`
      select chain_id, lower(target_address) as addr
      from contract_scans where target_address is not null
    `;
    const done = new Set(rows.map((r) => `${r.chain_id}:${r.addr}`));
    for (const item of items) {
      if (done.has(`${item.chainId}:${item.address}`)) {
        item.status = "skipped";
        skipped++;
      }
    }
  } catch (err) {
    sendJson(res, 500, {
      error: `could not check Supabase for already-saved addresses: ${err instanceof Error ? err.message : String(err)}`,
    });
    return;
  }

  status = {
    ...status,
    state: "running",
    total: items.length,
    completed: 0,
    failed: 0,
    skipped,
    current: null,
    startedAt: new Date().toISOString(),
    lastFlushAt: null,
    lastError: null,
    addressesFile,
    chainId,
    aiSecondPass,
    delayMs,
    pending: 0,
  };
  runCtx = { items, index: 0 };
  pauseRequested = false;
  stopRequested = false;
  runPromise = runLoop().catch((err) => {
    console.warn("[worker] run loop error:", err instanceof Error ? err.message : String(err));
  });
  writeStatusFile();
  console.log(`[worker] started: ${items.length} addresses (${skipped} already saved, skipped), chain=${chainId}, ai=${aiSecondPass}, delay=${delayMs}ms`);
  sendJson(res, 200, { ok: true, started: true, total: items.length, skipped });
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

  if (req.method === "GET" && url.pathname === "/status") {
    sendJson(res, 200, { ...status, pending: pending.length });
    return;
  }

  if (req.method === "POST" && url.pathname === "/start") {
    void handleStart(req, res);
    return;
  }

  if (req.method === "POST" && url.pathname === "/pause") {
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

  if (req.method === "POST" && url.pathname === "/resume") {
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

  if (req.method === "POST" && url.pathname === "/stop") {
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

  sendJson(res, 404, { error: "not found" });
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
  console.log(
    `[worker] DATABASE_URL ${process.env.DATABASE_URL ? "set" : "MISSING — set it in pipeline-worker/.env before starting a run"}`,
  );
  console.log(
    `[worker] OPENROUTER_API_KEY ${process.env.OPENROUTER_API_KEY ? "set" : "not set (AI second pass stays off unless requested)"}`,
  );
});
