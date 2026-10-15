import assert from "node:assert/strict";
import test from "node:test";
import { createSupabaseBatchWriter, saveBatchItemsToSupabase, toSupabaseBatchRow } from "./supabase.ts";
import type { BatchItem } from "./audit/address-fetcher.ts";

test("pending Supabase rows retry using corrected saved credentials", async () => {
  const original = globalThis.fetch;
  let cfg = { enabled: true, url: "https://example.supabase.co", anonKey: "sb_publishable_bad", tableName: "audits" };
  let saved = 0;
  globalThis.fetch = async (_url, init) => {
    if (new Headers(init?.headers).get("apikey") === "sb_publishable_bad") return new Response(null, { status: 403 });
    saved += JSON.parse(String(init?.body)).length;
    return new Response(null, { status: 201 });
  };
  const writer = createSupabaseBatchWriter(() => cfg);
  try {
    await writer.enqueue(toSupabaseBatchRow({ id: "same", address: "0x1", label: "Test", chainId: "base", status: "completed" }));
    await assert.rejects(writer.flush(), /403/);
    assert.equal(writer.stats.pendingCount, 1);
    cfg = { ...cfg, anonKey: "sb_publishable_corrected" };
    await writer.flush();
    assert.equal(saved, 1);
    assert.equal(writer.stats.pendingCount, 0);
  } finally { writer.dispose(); globalThis.fetch = original; }
});

test("Supabase writes a row array in one minimal-response request", async () => {
  const original = globalThis.fetch;
  let requests = 0;
  globalThis.fetch = async (url, init) => {
    requests++;
    assert.match(String(url), /on_conflict=id/);
    assert.equal(JSON.parse(String(init?.body)).length, 50);
    assert.match(new Headers(init?.headers).get("Prefer") ?? "", /return=minimal/);
    return new Response(null, { status: 201 });
  };
  try {
    const items = Array.from({ length: 50 }, (_, n) => ({
      id: `${n}`, address: `0x${n.toString(16).padStart(40, "0")}`,
      chainId: "ethereum", label: `${n}`, status: "completed",
    } as BatchItem));
    await saveBatchItemsToSupabase(items, { enabled: true, url: "https://example.supabase.co", anonKey: "sb_publishable_test", tableName: "audits" });
    assert.equal(requests, 1);
    globalThis.fetch = async () => new Response("denied", { status: 403 });
    await assert.rejects(saveBatchItemsToSupabase(items, { enabled: true, url: "https://example.supabase.co", anonKey: "sb_publishable_test", tableName: "audits" }), /403/);
  } finally { globalThis.fetch = original; }
});

test("browser sync rejects a secret key and unsafe table paths", async () => {
  const item = { id: "one", address: "0x1", label: "one", chainId: "ethereum", status: "completed" } as BatchItem;
  await assert.rejects(saveBatchItemsToSupabase([item], { enabled: true, url: "https://example.supabase.co", anonKey: "sb_secret_nope", tableName: "audits" }), /publishable|anon/i);
  await assert.rejects(saveBatchItemsToSupabase([item], { enabled: true, url: "https://example.supabase.co", anonKey: "sb_publishable_test", tableName: "../bad" }), /table/i);
});
