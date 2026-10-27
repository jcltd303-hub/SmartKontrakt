// pipeline-worker/proxy-follow.ts
//
// Follow a proxy to its implementation (2026-10-27).
//
// The pipeline's largest effectiveness gap: `analyzeAddress` fetches source for
// the address it was given, and `detectProxyArchitecture` correctly identifies
// EIP-1967 / transparent / minimal / Gnosis Safe proxies and returns the
// implementation addresses — which were persisted to `proxy_info_json` and
// mentioned in the report text, and never analysed. So a verified proxy produced
// findings from a ~50-line delegatecall shell, and an unverified one produced
// bytecode heuristics, while the logic that can actually be wrong sat unread in
// the implementation.
//
// This turns each implementation into its own queue entry. Everything downstream
// then applies unchanged: it gets its own source fetch, the 60 static rules,
// ResNet, its own findings row and its own `analyzer_version` stamp. The proxy's
// record keeps the link through `proxy_info_json`.

export type FollowedItem = {
  id: string;
  address: string;
  label: string;
  chainId: string;
  status: "pending";
};

/** The zero address is never an implementation; it is what a failed read returns. */
const ZERO = "0x0000000000000000000000000000000000000000";

export function dedupeKey(chainId: string, address: string): string {
  return `${chainId}:${address.toLowerCase()}`;
}

/**
 * Queue entries for a proxy's implementations.
 *
 * @param proxyInfo what detectProxyArchitecture returned (any shape; only
 *                  `implementations` is read)
 * @param chainId   the chain the proxy lives on — an implementation is analysed
 *                  on the same chain
 * @param seen      `dedupeKey` values already in the queue; not mutated here so
 *                  the caller decides when a key becomes "taken"
 */
export function implementationItems(
  proxyInfo: { implementations?: unknown } | null | undefined,
  chainId: string,
  seen: ReadonlySet<string>,
): FollowedItem[] {
  const raw = proxyInfo?.implementations;
  if (!Array.isArray(raw)) return [];
  const out: FollowedItem[] = [];
  const local = new Set<string>();
  for (const entry of raw) {
    const address = typeof entry === "string" ? entry : "";
    const addr = address.trim().toLowerCase();
    if (!/^0x[0-9a-f]{40}$/.test(addr)) continue;
    if (addr === ZERO) continue;
    const key = dedupeKey(chainId, addr);
    if (seen.has(key) || local.has(key)) continue;
    local.add(key);
    out.push({
      id: `impl-${addr}-${chainId}`,
      address: addr,
      label: `Implementation of proxy ${addr.slice(0, 6)}...${addr.slice(-4)}`,
      chainId,
      status: "pending",
    });
  }
  return out;
}
