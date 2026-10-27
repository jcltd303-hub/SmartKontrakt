// pipeline-worker/shard.ts
//
// Split an address list across N worker processes (2026-10-27).
//
// Measured: the worker processes ONE address at a time — `while (ctx.index <
// ctx.items.length)` — at ~7-20 s each, so 100k addresses is 8-23 days of wall
// clock from a single process. The work is I/O-bound (Sourcify, Blockscout, JSON
// RPC, 4byte), which is exactly what more processes scale, and the archive keys
// are (chain, address) so shards cannot collide.
//
// Deterministic and balanced: an address lands in the same shard every time, on
// every machine, because the partition is a hash of the address and not its
// position in the file. That matters for resume — a shard restarted tomorrow
// picks up the same addresses it had today, so `refresh: none` skips exactly what
// that shard already saved.

export type Shard = { index: number; of: number };

/** FNV-1a, 32-bit. Stable across processes and platforms, and dependency-free. */
export function hash32(input: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    // h *= 16777619, kept in 32-bit range
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h >>> 0;
}

/** Which shard an address belongs to. 1-based index, as the operator types it. */
export function shardOf(address: string, shard: Shard): number {
  if (shard.of <= 1) return 0;
  return hash32(address.trim().toLowerCase()) % shard.of;
}

/**
 * Parse `"2/4"` (or `{ index: 2, of: 4 }`) into a 1-based Shard.
 * Returns null for "no sharding", and throws on nonsense so a typo does not
 * silently analyse the whole list twice across four workers.
 */
export function parseShard(input: unknown): Shard | null {
  if (input === undefined || input === null || input === "") return null;
  let index: number;
  let of: number;
  if (typeof input === "string") {
    const m = input.trim().match(/^(\d+)\s*\/\s*(\d+)$/);
    if (!m) throw new Error(`shard must look like "2/4", got "${input}"`);
    index = Number(m[1]);
    of = Number(m[2]);
  } else if (typeof input === "object") {
    const o = input as { index?: unknown; of?: unknown };
    index = Number(o.index);
    of = Number(o.of);
  } else {
    throw new Error("shard must be a string like \"2/4\" or { index, of }");
  }
  if (!Number.isInteger(of) || of < 1) throw new Error(`shard "of" must be a positive integer, got ${of}`);
  if (!Number.isInteger(index) || index < 1 || index > of) {
    throw new Error(`shard "index" must be between 1 and ${of}, got ${index}`);
  }
  return of === 1 ? null : { index, of };
}

/** The items this shard owns, in their original order. */
export function applyShard<T extends { address: string }>(items: T[], shard: Shard | null): T[] {
  if (!shard) return items;
  const want = shard.index - 1;
  return items.filter((item) => shardOf(item.address, shard) === want);
}
