/**
 * Target ABI gathering + template tailoring.
 *
 * A fallback template only becomes a *working* PoC when its interface matches
 * the real contract. So the pipeline gathers the target's ABI once, stores it
 * with the scan (so any later PoC run — workbench, worker, CLI — can reuse it
 * without re-fetching), and tailors the chosen template's interface to the real
 * surface at PoC time.
 *
 * Sources, in order:
 *  1. Sourcify `metadata.json` (full_match, then partial_match) — keyless.
 *  2. Etherscan V2, when `ETHERSCAN_API_KEY` is set.
 *  3. A heuristic ABI rebuilt from what the analyzer already parsed: the
 *     function surface (with selectors resolved via 4byte) and the event topics.
 *
 * Tailoring is deliberately ADDITIVE: it prepends the real `ITarget` interface
 * and leaves the template body untouched, so it can never make a compiling
 * template stop compiling.
 */
import { rpcLimiter } from "./rate-limit.ts";
import { normalizeChainId } from "./balance.ts";

import type { AbiItem, Inventory } from "./types.ts";

export type { AbiItem };

export type GatheredAbi = { abi: AbiItem[]; source: "sourcify" | "etherscan" | "heuristic" };

async function getJson(url: string, timeoutMs = 12_000): Promise<unknown | null> {
  try {
    await rpcLimiter.acquire();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { headers: { Accept: "application/json" }, signal: controller.signal });
      if (!res.ok) return null;
      return await res.json();
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return null;
  }
}

/** Sourcify metadata carries the compiler's ABI verbatim. */
async function fromSourcify(address: string, chainId: number): Promise<AbiItem[] | null> {
  for (const kind of ["full_match", "partial_match"]) {
    const meta = (await getJson(
      `https://repo.sourcify.dev/contracts/${kind}/${chainId}/${address}/metadata.json`,
    )) as { output?: { abi?: AbiItem[] } } | null;
    const abi = meta?.output?.abi;
    if (Array.isArray(abi) && abi.length > 0) return abi;
  }
  return null;
}

/** Etherscan V2, only when a key is configured. */
async function fromEtherscan(address: string, chainId: number, apiKey: string): Promise<AbiItem[] | null> {
  const d = (await getJson(
    `https://api.etherscan.io/v2/api?chainid=${chainId}&module=contract&action=getabi&address=${address}&apikey=${apiKey}`,
  )) as { status?: string; result?: string } | null;
  if (!d || d.status !== "1" || typeof d.result !== "string") return null;
  try {
    const abi = JSON.parse(d.result) as AbiItem[];
    return Array.isArray(abi) && abi.length > 0 ? abi : null;
  } catch {
    return null;
  }
}

/**
 * Rebuild a usable ABI from the static analysis when no verified source exists:
 * every parsed function (name + params + mutability) and every resolved event.
 * This is what makes tailoring possible for unverified contracts.
 */
export function heuristicAbiFromInventory(inv: Inventory | null | undefined): AbiItem[] {
  if (!inv) return [];
  const items: AbiItem[] = [];
  const seen = new Set<string>();
  for (const fn of inv.functions ?? []) {
    const key = `${fn.name}(${fn.params})`;
    if (seen.has(key)) continue;
    seen.add(key);
    const inputs = splitParams(fn.params).map((type, i) => ({ name: `a${i}`, type }));
    const mutability = /view/i.test(fn.mutability)
      ? "view"
      : /pure/i.test(fn.mutability)
        ? "pure"
        : /payable/i.test(fn.mutability)
          ? "payable"
          : "nonpayable";
    items.push({ type: "function", name: fn.name, inputs, outputs: [], stateMutability: mutability });
  }
  for (const ev of inv.events ?? []) {
    // `events` are rendered signatures like "Transfer(address,address,uint256)".
    const m = /^([A-Za-z_$][\w$]*)\((.*)\)$/.exec(ev.trim());
    if (!m) continue;
    items.push({
      type: "event",
      name: m[1],
      inputs: splitParams(m[2]).map((type, i) => ({ name: `a${i}`, type, indexed: false } as never)),
    });
  }
  return items;
}

/** Split a Solidity parameter list, respecting nested tuples/arrays. */
export function splitParams(params: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of params) {
    if (ch === "(" || ch === "[") depth += 1;
    if (ch === ")" || ch === "]") depth -= 1;
    if (ch === "," && depth === 0) {
      if (cur.trim()) out.push(cur.trim());
      cur = "";
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** Gather the target ABI, or null when nothing could be found. */
export async function gatherAbi(
  address: string,
  chain: number | string | null | undefined,
  opts?: { inventory?: Inventory | null; etherscanKey?: string },
): Promise<GatheredAbi | null> {
  const chainId = normalizeChainId(chain);
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) return null;

  const sourcify = await fromSourcify(address, chainId);
  if (sourcify) return { abi: sourcify, source: "sourcify" };

  if (opts?.etherscanKey) {
    const etherscan = await fromEtherscan(address, chainId, opts.etherscanKey);
    if (etherscan) return { abi: etherscan, source: "etherscan" };
  }

  const heuristic = heuristicAbiFromInventory(opts?.inventory);
  if (heuristic.length > 0) return { abi: heuristic, source: "heuristic" };
  return null;
}

/** Solidity type for an ABI input, resolving tuples to a comment-safe fallback. */
function solidityType(input: { type?: string; components?: AbiItem[] }): string | null {
  const t = input.type;
  if (!t) return null;
  if (t.startsWith("tuple")) {
    // `(uint256,address)`-style; arrays keep their suffix.
    const inner = (input.components ?? []).map((c) => solidityType(c) ?? "bytes").join(",");
    return `(${inner})${t.slice("tuple".length)}`;
  }
  return t;
}

/** Render a Solidity interface from an ABI, for a template's target surface. */
export function interfaceFromAbi(abi: AbiItem[], name = "ITarget"): string {
  const lines: string[] = [`interface ${name} {`];
  let emitted = 0;
  for (const item of abi) {
    if (item.type && item.type !== "function") continue;
    if (!item.name) continue;
    const inputs = (item.inputs ?? []).map((i, idx) => {
      const type = solidityType(i);
      if (!type) return null;
      return `${type} ${i.name && /^[A-Za-z_$][\w$]*$/.test(i.name) ? i.name : `a${idx}`}`;
    });
    if (inputs.some((x) => x === null)) continue;
    const mut = item.stateMutability ?? "nonpayable";
    const outputs = (item.outputs ?? []).map((o) => solidityType(o)).filter((x): x is string => Boolean(x));
    const returns = outputs.length > 0 ? ` returns (${outputs.join(", ")})` : "";
    const mutWord = mut === "view" || mut === "pure" ? mut : mut === "payable" ? "payable" : "";
    lines.push(
      `    function ${item.name}(${(inputs as string[]).join(", ")}) external${mutWord ? ` ${mutWord}` : ""}${returns};`,
    );
    emitted += 1;
    if (emitted >= 80) break;
  }
  lines.push("}");
  return lines.join("\n");
}

/**
 * Prepend the real target surface to a template, additively. The template body
 * is untouched, so this never breaks a compiling template.
 */
export function tailorTemplateToAbi(templateSource: string, abi: AbiItem[], opts?: { name?: string; source?: string }): string {
  const name = opts?.name ?? "ITarget";
  const iface = interfaceFromAbi(abi, name);
  const fns = abi.filter((i) => !i.type || i.type === "function").length;
  const header = [
    `// ── TARGET SURFACE ──────────────────────────────────────────────────────────`,
    `// ${fns} function(s) gathered from the on-chain ABI${opts?.source ? ` (${opts.source})` : ""}.`,
    `// Wire the harness below to these real signatures; the template's own`,
    `// interface is a generic shape and will not match this target.`,
    iface,
    `// ────────────────────────────────────────────────────────────────────────────`,
    ``,
  ].join("\n");
  return `${header}${templateSource}`;
}
