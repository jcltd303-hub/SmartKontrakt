import assert from "node:assert/strict";
import test from "node:test";
import { BatchQueue, checkpointItem, restoreItem, retargetBatchQueue } from "./batch-queue.ts";
import type { BatchItem } from "./address-fetcher.ts";

test("changing the network creates fresh pending targets without old audit IDs", () => {
  const previous: BatchItem[] = [{ id: "eth", address: "0x1", label: "Test", chainId: "ethereum", status: "completed", scanId: "previous", persisted: true, riskScore: 80 }];
  const next = retargetBatchQueue(previous, "base");
  assert.equal(next[0].chainId, "base");
  assert.equal(next[0].status, "pending");
  assert.equal(next[0].scanId, undefined);
  assert.equal(next[0].riskScore, undefined);
  assert.equal(previous[0].scanId, "previous");
});

test("50k updates retain the queue array and maintain progress incrementally", () => {
  const model = new BatchQueue(Array.from({ length: 50_000 }, (_, i) => ({
    id: String(i), address: String(i), label: String(i), chainId: "base", status: "pending",
  } as BatchItem)));
  const items = model.items;
  for (let i = 0; i < items.length; i++) model.update(i, { status: "completed", criticalCount: 1, persisted: true });
  assert.equal(model.items, items);
  assert.equal(model.summary.completed, 50_000);
  assert.equal(model.summary.pending, 0);
  assert.equal(model.summary.totalCrit, 50_000);
});

test("checkpoints omit heavy payloads and requeue results not acknowledged by DB", () => {
  const item = { id: "one", address: "one", chainId: "base", label: "one", status: "completed", scanId: "stable", rawBody: "large", report: {} } as BatchItem;
  const lean = checkpointItem(item);
  assert.equal(lean.rawBody, undefined);
  assert.equal(lean.report, undefined);
  assert.equal(restoreItem(lean).status, "pending");
  assert.equal(restoreItem({ ...lean, persisted: true }).status, "completed");
  assert.equal(restoreItem(lean).scanId, "stable");
});
