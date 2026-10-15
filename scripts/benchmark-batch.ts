import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { AsyncBatchWriter } from "../src/lib/audit/batch-writer.ts";
import { BatchQueue } from "../src/lib/audit/batch-queue.ts";
import { writeAuditBatch } from "../src/lib/audit/bulk-persist.server.ts";
import { createSqlClient } from "../src/lib/sql-client.ts";
import type { ComprehensiveRecordInput } from "../src/lib/audit/persist.server.ts";
import { record } from "./audit-fixture.ts";

// Entirely synthetic. No public RPC, chain interaction, or production data.
const useDatabase = process.argv.includes("--database");
const count = 50_000;
const pg = useDatabase ? new PGlite() : null;
let queries = 0;
if (pg) {
  await pg.waitReady;
  for (const f of ["0002_scans.sql", "0003_comprehensive_records_and_rag.sql"]) {
    await pg.exec(await readFile(new URL(`../migrations/${f}`, import.meta.url), "utf8"));
  }
}
const sql = pg ? createSqlClient(
  async <T>(text: string, params: unknown[]) => { queries++; return (await pg.query<T>(text, params)).rows; },
  (work) => pg.transaction((tx) => work(async <T>(text: string, params: unknown[]) => {
    queries++; return (await tx.query<T>(text, params)).rows;
  })),
) : null;
const model = new BatchQueue(Array.from({ length: count }, (_, i) => ({
  id: `synthetic-${i}`, scanId: `synthetic-${i}`,
  address: `0x${i.toString(16).padStart(40, "0")}`,
  label: `Synthetic ${i}`, chainId: "ethereum", status: "pending",
})));
let batches = 0;
let rowsWritten = 0;
let peakPending = 0;
let peakPendingBytes = 0;
const started = performance.now();
const heapStart = process.memoryUsage().heapUsed;
let peakHeap = heapStart;
const writer = new AsyncBatchWriter<ComprehensiveRecordInput>({
  write: async (records) => {
    if (sql) await writeAuditBatch(sql, records);
    for (const r of records) model.update(Number(r.id!.slice("synthetic-".length)), { persisted: true });
    rowsWritten += records.length; batches++;
    if (batches % 100 === 0) console.error(`[benchmark] ${rowsWritten.toLocaleString()} / ${count.toLocaleString()}`);
  },
  onChange: (s) => {
    peakPending = Math.max(peakPending, s.pendingCount);
    peakPendingBytes = Math.max(peakPendingBytes, s.pendingBytes);
    peakHeap = Math.max(peakHeap, process.memoryUsage().heapUsed);
  },
});
try {
  for (let i = 0; i < count; i++) {
    const item = model.items[i];
    model.update(i, { status: "analyzing" });
    const dossier = record(item.id);
    dossier.targetAddress = item.address;
    await writer.enqueue(dossier);
    model.update(i, { status: "completed", findingsCount: 2, highCount: 2 });
  }
  await writer.flush();
  assert.equal(rowsWritten, count);
  assert.equal(model.summary.completed, count);
  assert.ok(peakPending <= 100);
  assert.ok(peakPendingBytes <= 8_000_000);
  if (pg) {
    const totals = await pg.query<{ scans: number; findings: number; chunks: number }>(`
      select (select count(*)::int from contract_scans) as scans,
             (select count(*)::int from findings) as findings,
             (select count(*)::int from rag_knowledge_chunks) as chunks`);
    assert.deepEqual(totals.rows[0], { scans: count, findings: count * 2, chunks: count * 3 });
  }
  console.log(JSON.stringify({
    mode: pg ? "local-postgres-pglite" : "in-memory-sink", addresses: count, batches,
    dataStatements: queries, peakBufferedRecords: peakPending, peakBufferedBytes: peakPendingBytes,
    seconds: Number(((performance.now() - started) / 1000).toFixed(2)),
    peakJsHeapMiB: Number((peakHeap / 1024 ** 2).toFixed(2)),
    heapGrowthMiB: Number(((peakHeap - heapStart) / 1024 ** 2).toFixed(2)),
    note: "Synthetic dossiers; local database memory is included when --database is used.",
  }, null, 2));
} finally { writer.dispose(); await pg?.close(); }
