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
  // ProxyAnalysis calls it `implementationAddress`, singular. This parameter used to
  // declare `implementations`, so the lookup read a property the object does not have:
  // Array.isArray(undefined) is false, the function returned [] every time, and no
  // implementation was ever queued. That is the whole reason 47.8 ETH sat behind proxies
  // scored "Clean". Both spellings are accepted now so neither shape can silently miss.
  proxyInfo: { implementations?: unknown; implementationAddress?: unknown } | null | undefined,
  chainId: string,
  seen: ReadonlySet<string>,
  runtimeBytecode?: string | null,
): FollowedItem[] {
  // Union of what the resolver reports and what the code says. The resolver is often
  // empty for EIP-1167 clones; the bytecode never is.
  const raw: unknown[] = [];
  if (Array.isArray(proxyInfo?.implementations)) raw.push(...proxyInfo!.implementations);
  const single = proxyInfo?.implementationAddress;
  if (typeof single === "string" && single.trim()) raw.push(single);
  for (const addr of implementationsFromBytecode(runtimeBytecode)) raw.push(addr);
  if (raw.length === 0) return [];
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

/**
 * Implementation addresses that are IN the runtime bytecode, independent of any registry.
 *
 * Why this exists (2026-10-31): 47.8 ETH sat behind MinimalProxies the pipeline had
 * scored 2/100 "Clean". The shell is ~45 bytes of delegatecall, so "clean" is true and
 * meaningless — the logic is in the implementation, and the implementation was never
 * queued. `implementationItems` only followed `proxyInfo.implementations`, which
 * Blockscout leaves empty for many EIP-1167 clones. The address is right there in the
 * code, so read it from the code.
 */
export function implementationsFromBytecode(bytecode: string | null | undefined): string[] {
  if (!bytecode) return [];
  const code = bytecode.toLowerCase().replace(/^0x/, "");
  const found: string[] = [];

  // EIP-1167 minimal proxy, both the canonical and the 3d3d3d3d variant:
  //   363d3d373d3d3d363d73 <address> 5af43d82803e903d91602b57fd5bf3
  //   3d3d3d3d363d73       <address> 5af43d3d93803e602a57fd5bf3
  for (const m of code.matchAll(/363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3/g)) {
    found.push(`0x${m[1]}`);
  }
  for (const m of code.matchAll(/3d3d3d3d363d73([0-9a-f]{40})5af43d3d93803e602a57fd5bf3/g)) {
    found.push(`0x${m[1]}`);
  }
  return [...new Set(found)];
}

/** EIP-1967 implementation slot, as the 32-byte key eth_getStorageAt expects. */
export const EIP1967_IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

/** A 32-byte storage word holding an address -> that address, or null. */
export function addressFromStorageWord(word: string | null | undefined): string | null {
  if (!word) return null;
  const hex = word.toLowerCase().replace(/^0x/, "");
  if (hex.length < 40) return null;
  const addr = `0x${hex.slice(-40)}`;
  return /^0x0{40}$/.test(addr) ? null : addr;
}
