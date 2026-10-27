import test from "node:test";
import assert from "node:assert/strict";

import { clearFourbyteUpstreamMemo, createOnDemandFourbyteLookup } from "./fourbyte.ts";

/**
 * Negative caching (2026-10-27).
 *
 * Measured on a live run: 54 scans in 18 minutes, 20 s per address, 242 resolved
 * signatures. On a bytecode-only contract every selector is unknown, so the cost
 * was N selectors / 8 lanes x a 5 s upstream timeout — and only HITS were cached,
 * so every contract in the run paid the same misses again.
 *
 * These drive the real resolveBatch through a fake SQL client, so the query text,
 * the skip logic and the miss write are all exercised.
 */

// The upstream memo is module-level and outlives a test: a selector pulled in one
// test would answer from memory in the next, silently changing its reason. Clear it
// between tests, which is what the worker does on a fresh run anyway.
test.beforeEach(() => clearFourbyteUpstreamMemo());

type Query = { text: string; values: unknown[] };

function fakeSql(opts: { hits?: Map<string, string>; misses?: Set<string> } = {}) {
  const hits = opts.hits ?? new Map<string, string>();
  const misses = opts.misses ?? new Set<string>();
  const queries: Query[] = [];
  const inserts: { table: string; keys: string[]; reason?: string }[] = [];

  const sql = async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const text = strings.join("?").replace(/\s+/g, " ").trim();
    queries.push({ text, values });
    if (text.includes("from fourbyte_signatures")) {
      const keys = values[0] as string[];
      return [...hits.entries()]
        .filter(([k]) => keys.includes(k))
        .map(([k, v]) => ({ selector: k, signature: v }));
    }
    if (text.includes("from fourbyte_event_signatures")) {
      return [];
    }
    if (text.startsWith("select key from fourbyte_misses")) {
      const keys = values[1] as string[];
      return keys.filter((k) => misses.has(k)).map((k) => ({ key: k }));
    }
    if (text.startsWith("insert into fourbyte_misses")) {
      // Parameter order follows appearance in the SQL:
      // `select ${kind}, k, now(), ${reason} from unnest(${uniq}::text[])`
      // so values[0] kind, values[1] reason, values[2] key array.
      inserts.push({ table: "fourbyte_misses", keys: values[2] as string[], reason: String(values[1]) });
      return [];
    }
    if (text.startsWith("insert into fourbyte_signatures")) {
      inserts.push({ table: "fourbyte_signatures", keys: [String(values[1])] });
      return [];
    }
    return [];
  };
  return { sql, queries, inserts };
}

function fakeFetch(answer: (hex: string) => unknown) {
  const asked: string[] = [];
  const impl = async (url: string) => {
    const hex = decodeURIComponent(url.split("hex_signature=")[1] ?? "");
    asked.push(hex);
    const body = answer(hex);
    if (body === null) return { ok: false, json: async () => ({}) } as never;
    return { ok: true, json: async () => body } as never;
  };
  return { impl, asked };
}

const HIT = (sig: string) => ({ results: [{ id: 1, text_signature: sig }] });
const NONE = { results: [] };

test("a recently-missed selector is never sent upstream", async () => {
  const db = fakeSql({ misses: new Set(["0xaaaaaaaa"]) });
  const net = fakeFetch(() => NONE);
  const lookup = createOnDemandFourbyteLookup(db.sql as never, { fetchImpl: net.impl });

  const out = await lookup.selectors(["0xaaaaaaaa", "0xbbbbbbbb"]);

  assert.deepEqual(net.asked, ["0xbbbbbbbb"], "only the un-missed key goes upstream");
  assert.equal(out.size, 0, "neither resolved");
});

test("an empty 200 is recorded as an authoritative miss", async () => {
  const db = fakeSql();
  const net = fakeFetch(() => NONE);
  const lookup = createOnDemandFourbyteLookup(db.sql as never, { fetchImpl: net.impl });

  await lookup.selectors(["0xdeadbeef"]);

  const missWrites = db.inserts.filter((i) => i.table === "fourbyte_misses");
  assert.equal(missWrites.length, 1, "one batched miss write, not one per key");
  assert.deepEqual(missWrites[0]!.keys, ["0xdeadbeef"]);
  assert.equal(missWrites[0]!.reason, "unknown", "the API answered and does not know it");
});

test("a timeout is recorded as unreachable, not as a fact about the selector", async () => {
  // The distinction that matters: an outage must not teach the cache that a
  // perfectly well-known selector does not exist. 144 misses were recorded in the
  // first 20 minutes with nothing in the schema able to say which were real.
  const db = fakeSql();
  const net = fakeFetch(() => null); // non-OK response
  const lookup = createOnDemandFourbyteLookup(db.sql as never, { fetchImpl: net.impl });

  await lookup.selectors(["0x12345678"]);

  const missWrites = db.inserts.filter((i) => i.table === "fourbyte_misses");
  assert.equal(missWrites.length, 1);
  assert.equal(missWrites[0]!.reason, "unreachable");
});

test("a known and an unreachable selector in one batch are recorded separately", async () => {
  const db = fakeSql();
  const net = fakeFetch((hex) => (hex === "0xaaaaaaaa" ? NONE : null));
  const lookup = createOnDemandFourbyteLookup(db.sql as never, { fetchImpl: net.impl });

  await lookup.selectors(["0xaaaaaaaa", "0xbbbbbbbb"]);

  const byReason = new Map(db.inserts.filter((i) => i.table === "fourbyte_misses").map((i) => [i.reason, i.keys]));
  assert.deepEqual(byReason.get("unknown"), ["0xaaaaaaaa"]);
  assert.deepEqual(byReason.get("unreachable"), ["0xbbbbbbbb"]);
});

test("an answered selector is cached as a hit and not as a miss", async () => {
  const db = fakeSql();
  const net = fakeFetch(() => HIT("transfer(address,uint256)"));
  const lookup = createOnDemandFourbyteLookup(db.sql as never, { fetchImpl: net.impl });

  const out = await lookup.selectors(["0xa9059cbb"]);

  assert.deepEqual(out.get("0xa9059cbb"), ["transfer(address,uint256)"]);
  assert.equal(db.inserts.filter((i) => i.table === "fourbyte_misses").length, 0);
  assert.equal(db.inserts.filter((i) => i.table === "fourbyte_signatures").length, 1);
});

test("a cached hit is not sent upstream either", async () => {
  const db = fakeSql({ hits: new Map([["0xa9059cbb", "transfer(address,uint256)"]]) });
  const net = fakeFetch(() => NONE);
  const lookup = createOnDemandFourbyteLookup(db.sql as never, { fetchImpl: net.impl });

  const out = await lookup.selectors(["0xa9059cbb"]);
  assert.deepEqual(net.asked, [], "served from the cache");
  assert.deepEqual(out.get("0xa9059cbb"), ["transfer(address,uint256)"]);
});

test("a missing fourbyte_misses table degrades to the old behaviour", async () => {
  // The table is created by migration 0020; a database without it must not break
  // enrichment, it must simply lose the optimisation.
  const sql = async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const text = strings.join("?").replace(/\s+/g, " ").trim();
    if (text.includes("fourbyte_misses")) throw new Error('relation "fourbyte_misses" does not exist');
    if (text.includes("from fourbyte_signatures")) return [];
    void values;
    return [];
  };
  const net = fakeFetch(() => NONE);
  const lookup = createOnDemandFourbyteLookup(sql as never, { fetchImpl: net.impl });

  await lookup.selectors(["0xcccccccc"]);
  assert.deepEqual(net.asked, ["0xcccccccc"], "still asks upstream when the cache is unusable");
});
