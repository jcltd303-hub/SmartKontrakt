import assert from "node:assert/strict";
import test from "node:test";
import type { Sql } from "../sql-client.ts";
import {
  clearFourbyteUpstreamMemo,
  createOnDemandFourbyteLookup,
  type FourbyteFetchLike,
} from "./fourbyte.ts";

/**
 * On-demand 4byte resolution (2026-10-22): cache-first, live pull on
 * miss, canonical = lowest registration id, graceful null everywhere.
 * Fetch is mocked — no live network in unit tests.
 */

type SelRow = { selector: string; signature: string };
type TopRow = { topic: string; signature: string };

function fakeSql(opts?: { failSelect?: boolean; failInsert?: boolean }) {
  const sels: SelRow[] = [];
  const tops: TopRow[] = [];
  const tag = async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const text = strings.join(" ").replace(/\s+/g, " ");
    if (text.includes("select selector, signature from fourbyte_signatures")) {
      if (opts?.failSelect) throw new Error('relation "fourbyte_signatures" does not exist');
      const keys = values[0] as string[];
      return sels.filter((r) => keys.includes(r.selector));
    }
    if (text.includes("select topic, signature from fourbyte_event_signatures")) {
      if (opts?.failSelect) throw new Error('relation "fourbyte_event_signatures" does not exist');
      const keys = values[0] as string[];
      return tops.filter((r) => keys.includes(r.topic));
    }
    if (text.includes("insert into fourbyte_signatures")) {
      if (opts?.failInsert) throw new Error('relation "fourbyte_signatures" does not exist');
      sels.push({ selector: values[0] as string, signature: values[1] as string });
      return [];
    }
    if (text.includes("insert into fourbyte_event_signatures")) {
      if (opts?.failInsert) throw new Error('relation "fourbyte_event_signatures" does not exist');
      tops.push({ topic: values[0] as string, signature: values[1] as string });
      return [];
    }
    return [];
  };
  const sql = Object.assign(tag, {
    query: async () => [],
    transaction: async () => {
      throw new Error("not used in fourbyte tests");
    },
  }) as unknown as Sql;
  return { sql, sels, tops };
}

function fakeFetch(handler: (url: string) => { status?: number; body?: unknown } | "throw") {
  const calls: string[] = [];
  const impl: FourbyteFetchLike = async (url: string) => {
    calls.push(url);
    const r = handler(url);
    if (r === "throw") throw new Error("network down");
    return {
      ok: (r.status ?? 200) >= 200 && (r.status ?? 200) < 300,
      status: r.status ?? 200,
      json: async () => r.body ?? {},
    };
  };
  return { impl, calls };
}

/** API bodies are newest-first: higher ids come before lower ids. */
const apiBody = (rows: { id: number; text_signature: string; hex_signature: string }[]) => ({
  count: rows.length,
  next: null,
  previous: null,
  results: rows,
});

const TRANSFER = "0xa9059cbb";
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

test("cache hit: zero fetches, cached signatures returned", async () => {
  clearFourbyteUpstreamMemo();
  const { sql, sels } = fakeSql();
  sels.push({ selector: TRANSFER, signature: "transfer(address,uint256)" });
  const { impl, calls } = fakeFetch(() => ({ body: apiBody([]) }));
  const lookup = createOnDemandFourbyteLookup(sql, { fetchImpl: impl });
  const out = await lookup.selectors([TRANSFER]);
  assert.deepEqual(out.get(TRANSFER), ["transfer(address,uint256)"]);
  assert.equal(calls.length, 0);
});

test("cache miss: one fetch, canonical (lowest id) first, pulled rows cached", async () => {
  clearFourbyteUpstreamMemo();
  const { sql, sels } = fakeSql();
  const { impl, calls } = fakeFetch(() => ({
    body: apiBody([
      { id: 1111734, text_signature: "workMyDirefulOwner(uint256,uint256)", hex_signature: TRANSFER },
      { id: 145, text_signature: "transfer(address,uint256)", hex_signature: TRANSFER },
    ]),
  }));
  const lookup = createOnDemandFourbyteLookup(sql, { fetchImpl: impl });
  const out = await lookup.selectors([TRANSFER]);
  assert.deepEqual(out.get(TRANSFER), ["transfer(address,uint256)", "workMyDirefulOwner(uint256,uint256)"]);
  assert.equal(calls.length, 1);
  assert.ok(calls[0]!.includes("/api/v1/signatures/?hex_signature=0xa9059cbb"));
  assert.equal(sels.length, 2);
  assert.ok(sels.some((r) => r.signature === "transfer(address,uint256)"));
});

test("dedupe: repeat lookups of the same selector cost one fetch total", async () => {
  clearFourbyteUpstreamMemo();
  const { impl, calls } = fakeFetch(() => ({
    body: apiBody([{ id: 1, text_signature: "foo()", hex_signature: "0x11111111" }]),
  }));
  const lookup = createOnDemandFourbyteLookup(null, { fetchImpl: impl });
  await lookup.selectors(["0x11111111", "0x11111111"]);
  await lookup.selectors(["0x11111111"]);
  assert.equal(calls.length, 1);
});

test("upstream 500: key absent, no throw", async () => {
  clearFourbyteUpstreamMemo();
  const { sql } = fakeSql();
  const { impl } = fakeFetch(() => ({ status: 500, body: {} }));
  const lookup = createOnDemandFourbyteLookup(sql, { fetchImpl: impl });
  const out = await lookup.selectors(["0x22222222"]);
  assert.equal(out.has("0x22222222"), false);
});

test("upstream network throw: key absent, no throw", async () => {
  clearFourbyteUpstreamMemo();
  const { sql } = fakeSql();
  const { impl } = fakeFetch(() => "throw");
  const lookup = createOnDemandFourbyteLookup(sql, { fetchImpl: impl });
  const out = await lookup.selectors(["0x33333333"]);
  assert.equal(out.has("0x33333333"), false);
});

test("unregistered selector (empty results): key absent, nothing cached", async () => {
  clearFourbyteUpstreamMemo();
  const { sql, sels } = fakeSql();
  const { impl } = fakeFetch(() => ({ body: apiBody([]) }));
  const lookup = createOnDemandFourbyteLookup(sql, { fetchImpl: impl });
  const out = await lookup.selectors(["0x44444444"]);
  assert.equal(out.has("0x44444444"), false);
  assert.equal(sels.length, 0);
});

test("missing cache table: live fetch still returns the signature, insert failure swallowed", async () => {
  clearFourbyteUpstreamMemo();
  const { sql } = fakeSql({ failSelect: true, failInsert: true });
  const { impl, calls } = fakeFetch(() => ({
    body: apiBody([{ id: 145, text_signature: "transfer(address,uint256)", hex_signature: TRANSFER }]),
  }));
  const lookup = createOnDemandFourbyteLookup(sql, { fetchImpl: impl });
  const out = await lookup.selectors([TRANSFER]);
  assert.deepEqual(out.get(TRANSFER), ["transfer(address,uint256)"]);
  assert.equal(calls.length, 1);
});

test("null sql (no DB at all): cache-less live pull works", async () => {
  clearFourbyteUpstreamMemo();
  const { impl } = fakeFetch(() => ({
    body: apiBody([{ id: 7, text_signature: "bar(uint256)", hex_signature: "0x55555555" }]),
  }));
  const lookup = createOnDemandFourbyteLookup(null, { fetchImpl: impl });
  const out = await lookup.selectors(["0x55555555"]);
  assert.deepEqual(out.get("0x55555555"), ["bar(uint256)"]);
});

test("event topics: miss pulls from the event-signatures endpoint and caches", async () => {
  clearFourbyteUpstreamMemo();
  const { sql, tops } = fakeSql();
  const { impl, calls } = fakeFetch(() => ({
    body: apiBody([{ id: 1, text_signature: "Transfer(address,address,uint256)", hex_signature: TRANSFER_TOPIC }]),
  }));
  const lookup = createOnDemandFourbyteLookup(sql, { fetchImpl: impl });
  const out = await lookup.topics([TRANSFER_TOPIC]);
  assert.deepEqual(out.get(TRANSFER_TOPIC), ["Transfer(address,address,uint256)"]);
  assert.equal(calls.length, 1);
  assert.ok(calls[0]!.includes("/api/v1/event-signatures/?hex_signature=0xddf252ad"));
  assert.equal(tops.length, 1);
});

test("event topics: cache hit costs no fetch", async () => {
  clearFourbyteUpstreamMemo();
  const { sql, tops } = fakeSql();
  tops.push({ topic: TRANSFER_TOPIC, signature: "Transfer(address,address,uint256)" });
  const { impl, calls } = fakeFetch(() => ({ body: apiBody([]) }));
  const lookup = createOnDemandFourbyteLookup(sql, { fetchImpl: impl });
  const out = await lookup.topics([TRANSFER_TOPIC]);
  assert.deepEqual(out.get(TRANSFER_TOPIC), ["Transfer(address,address,uint256)"]);
  assert.equal(calls.length, 0);
});
