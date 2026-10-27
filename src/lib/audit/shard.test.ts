import test from "node:test";
import assert from "node:assert/strict";

import { applyShard, hash32, parseShard, shardOf } from "../../../pipeline-worker/shard.ts";

/**
 * Sharding the address list across worker processes (2026-10-27).
 *
 * The worker is serial per address at ~7-20 s, so 100k is 8-23 days from one
 * process. Shards must be deterministic (resume picks up the same addresses),
 * disjoint (no address analysed twice) and balanced (no shard finishes last).
 */

const addrs = Array.from({ length: 4000 }, (_, i) => `0x${(i + 1).toString(16).padStart(40, "0")}`);
/** applyShard works on queue items, not bare strings. */
const items = addrs.map((address) => ({ address }));

test("the partition is deterministic: same address, same shard, always", () => {
  for (const a of addrs.slice(0, 200)) {
    assert.equal(shardOf(a, { index: 2, of: 4 }), shardOf(a, { index: 2, of: 4 }));
  }
});

test("shards are disjoint and complete: every address lands in exactly one", () => {
  for (const of of [2, 3, 4, 8]) {
    const seen = new Map<string, number>();
    for (let i = 1; i <= of; i++) {
      for (const item of applyShard(items, { index: i, of })) {
        assert.equal(seen.has(item.address), false, `${item.address} appears in two shards of ${of}`);
        seen.set(item.address, i);
      }
    }
    assert.equal(seen.size, addrs.length, `of=${of} covers every address`);
  }
});

test("shards are balanced within 5% of even", () => {
  for (const of of [2, 4, 8]) {
    const sizes = Array.from({ length: of }, (_, i) => applyShard(items, { index: i + 1, of }).length);
    const even = addrs.length / of;
    for (const n of sizes) {
      assert.ok(Math.abs(n - even) / even < 0.05, `of=${of} sizes ${sizes.join(",")} vs even ${even}`);
    }
  }
});

test("case does not move an address between shards", () => {
  const a = "0xABCDEF0000000000000000000000000000000001";
  assert.equal(shardOf(a, { index: 1, of: 4 }), shardOf(a.toLowerCase(), { index: 1, of: 4 }));
});

test("one shard of one is no sharding at all", () => {
  assert.equal(parseShard("1/1"), null);
  assert.deepEqual(applyShard(items, parseShard("1/1")), items);
});

test("parsing accepts the operator's forms and rejects nonsense loudly", () => {
  assert.deepEqual(parseShard("2/4"), { index: 2, of: 4 });
  assert.deepEqual(parseShard(" 3 / 8 "), { index: 3, of: 8 });
  assert.deepEqual(parseShard({ index: 1, of: 4 }), { index: 1, of: 4 });
  assert.equal(parseShard(undefined), null);
  assert.equal(parseShard(""), null);
  // A typo must not silently analyse the whole list on every worker.
  assert.throws(() => parseShard("0/4"), /between 1 and 4/);
  assert.throws(() => parseShard("5/4"), /between 1 and 4/);
  assert.throws(() => parseShard("2/0"), /positive integer/);
  assert.throws(() => parseShard("half"), /look like/);
});

test("hash32 is stable and 32-bit", () => {
  assert.equal(hash32("0xabc"), hash32("0xabc"));
  assert.notEqual(hash32("0xabc"), hash32("0xabd"));
  for (const s of ["", "a", "0x" + "f".repeat(40)]) {
    const h = hash32(s);
    assert.ok(h >= 0 && h <= 0xffffffff, `${h} out of range`);
  }
});
