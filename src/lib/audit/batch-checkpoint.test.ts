import "fake-indexeddb/auto";
import assert from "node:assert/strict";
import test from "node:test";
import { initializeBatchQueue, loadBatchCheckpoint, saveBatchCheckpoint } from "./batch-checkpoint.ts";
import { BatchQueue } from "./batch-queue.ts";
import type { BatchItem } from "./address-fetcher.ts";

test("a fresh run checkpoints the whole pending tail before dirty-slot updates", async () => {
  const queue = new BatchQueue(Array.from({ length: 5 }, (_, i) => ({
    id: String(i), address: String(i), label: String(i), chainId: "base", status: "pending",
  })));
  await initializeBatchQueue(queue);
  queue.update(0, { status: "completed", persisted: true });
  await saveBatchCheckpoint([[0, queue.items[0]]]);
  const restored = await loadBatchCheckpoint();
  assert.equal(restored?.length, 5);
  assert.equal(restored?.[4].status, "pending");
});

test("a 50k queue restores all rows and checkpoints only changed slots", async () => {
  const rows: [number, BatchItem][] = Array.from({ length: 50_000 }, (_, index) => [index, {
    id: String(index), address: `0x${index.toString(16).padStart(40, "0")}`,
    chainId: "base", label: String(index), status: "pending", scanId: `stable-${index}`,
  }]);
  await saveBatchCheckpoint(rows, true);
  await saveBatchCheckpoint([[49_999, { ...rows[49_999][1], status: "completed", persisted: true, supabaseSynced: false, summary: "Remote write still pending" }]]);
  const restored = await loadBatchCheckpoint();
  assert.equal(restored?.length, 50_000);
  assert.equal(restored?.[49_999].status, "completed");
  assert.equal(restored?.[49_999].supabaseSynced, false);
  assert.equal(restored?.[49_999].summary, "Remote write still pending");
  assert.equal(restored?.[100].scanId, "stable-100");
  await saveBatchCheckpoint([rows[0]], true);
  assert.equal((await loadBatchCheckpoint())?.length, 1);
  await saveBatchCheckpoint([], true);
  assert.deepEqual(await loadBatchCheckpoint(), []);
});
