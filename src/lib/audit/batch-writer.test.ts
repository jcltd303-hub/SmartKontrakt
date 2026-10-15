import assert from "node:assert/strict";
import test from "node:test";
import { AsyncBatchWriter, ByteLruCache } from "./batch-writer.ts";

test("50,000 records use bounded batches and one active write", async () => {
  let written = 0;
  let calls = 0;
  let active = 0;
  let peakItems = 0;
  let peakBytes = 0;
  const writer = new AsyncBatchWriter<{ id: number }>({
    batchSize: 50, maxBatchBytes: 3200, maxBufferedItems: 100,
    maxBufferedBytes: 6400, sizeOf: () => 64,
    write: async (batch) => {
      assert.equal(++active, 1);
      assert.ok(batch.length <= 50);
      await new Promise<void>((resolve) => setImmediate(resolve));
      written += batch.length;
      calls++;
      active--;
    },
    onChange: (s) => {
      peakItems = Math.max(peakItems, s.pendingCount);
      peakBytes = Math.max(peakBytes, s.pendingBytes);
    },
  });
  for (let id = 0; id < 50_000; id++) await writer.enqueue({ id });
  await Promise.all([writer.flush(), writer.flush()]);
  writer.dispose();
  assert.equal(written, 50_000);
  assert.equal(calls, 1000);
  assert.ok(peakItems <= 100);
  assert.ok(peakBytes <= 6400);
  assert.equal(writer.stats.pendingCount, 0);
});

test("failed writes retain stable records and backpressure stops growth", async () => {
  let failing = true;
  const stored = new Map<number, string>();
  const writer = new AsyncBatchWriter<{ id: number; body: string }>({
    batchSize: 2, maxBufferedItems: 2, maxRetries: 0,
    write: async (batch) => {
      for (const r of batch) stored.set(r.id, r.body);
      if (failing) throw new Error("response lost after commit");
    },
  });
  await writer.enqueue({ id: 1, body: "one" });
  await writer.enqueue({ id: 2, body: "two" });
  await assert.rejects(writer.flush(), /response lost/);
  await assert.rejects(writer.enqueue({ id: 3, body: "three" }), /response lost/);
  assert.equal(writer.stats.pendingCount, 2);
  failing = false;
  await writer.flush();
  assert.equal(stored.size, 2);
  assert.equal(writer.stats.totalFlushed, 2);
  writer.dispose();
});

test("byte limits split batches and reject a single oversized dossier", async () => {
  const sizes: number[] = [];
  const writer = new AsyncBatchWriter<string>({
    batchSize: 50, maxBatchBytes: 10, maxBufferedBytes: 20,
    sizeOf: (s) => new TextEncoder().encode(s).byteLength,
    write: async (batch) => { sizes.push(batch.join("").length); },
  });
  for (let i = 0; i < 5; i++) await writer.enqueue("123456");
  await writer.flush();
  assert.deepEqual(sizes, [6, 6, 6, 6, 6]);
  await assert.rejects(writer.enqueue("12345678901"), /exceeds/i);
  writer.dispose();
});

test("transient failures retry with a finite budget and low traffic flushes", async () => {
  let attempts = 0;
  const writer = new AsyncBatchWriter<number>({
    flushIntervalMs: 5, retryDelayMs: 1, maxRetries: 2,
    write: async () => { if (++attempts < 3) throw new Error("temporarily unavailable"); },
  });
  await writer.enqueue(1);
  await new Promise<void>((resolve) => setTimeout(resolve, 30));
  assert.equal(attempts, 3);
  assert.equal(writer.stats.pendingCount, 0);
  writer.dispose();
  await assert.rejects(writer.enqueue(2), /closed/);
});

test("inspection cache evicts by bytes and refreshes recently used entries", () => {
  const cache = new ByteLruCache<string>(3, 10, (s) => s.length);
  cache.set("ethereum:one", "1234");
  cache.set("base:one", "5678");
  assert.equal(cache.get("ethereum:one"), "1234");
  cache.set("ethereum:two", "abcd");
  assert.equal(cache.get("base:one"), undefined);
  assert.equal(cache.size, 2);
  cache.set("large", "12345678901");
  assert.equal(cache.get("large"), undefined);
  assert.ok(cache.bytes <= 10);
});
