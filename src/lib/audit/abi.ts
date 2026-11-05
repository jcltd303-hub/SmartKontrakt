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
 *  3. The Solidity source this scan already fetched, parsed directly. Exact
 *     signatures, no selector guessing.
 *  4. A heuristic ABI rebuilt from what the analyzer already parsed: the
 *     function surface (with selectors resolved via 4byte) and the event topics.
 *
 * Tailoring is deliberately ADDITIVE: it prepends the real `ITarget` interface
 * and leaves the template body untouched, so it can never make a compiling
 * template stop compiling.
 */
import parser from "@solidity-parser/parser";
import { rpcLimiter } from "./rate-limit.ts";
import { normalizeChainId } from "./balance.ts";

import type { AbiItem, Inventory } from "./types.ts";

export type { AbiItem };

export type GatheredAbi = { abi: AbiItem[]; source: "sourcify" | "etherscan" | "source" | "heuristic" };

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

/**
 * Build an ABI from Solidity source that was already fetched.
 *
 * Every scan that stores `input_kind = 'source'` holds the contract text in
 * `scan_payloads.body`, yet the ABI recorded alongside it was `heuristic` for 66 of 66 such
 * contracts in a measured page (2026-11-06). The heuristic resolves selectors through 4byte,
 * which the generator prompt itself calls "hypotheses, not verified call surfaces" — so the
 * PoC path was being handed guesses for three quarters of the archive while the exact
 * source sat in the same row. That is the ABI-mismatch half of the failed PoC runs.
 *
 * Parses with @solidity-parser/parser (already a dependency) and emits only what the source
 * declares. Returns [] on any parse failure so the caller falls through to the heuristic —
 * a malformed file must not lose the ABI entirely.
 */
export function abiFromSoliditySource(source: string, contractName?: string): AbiItem[] {
  if (!source || source.length < 40) return [];
  // Hex bytecode is not source.
  if (/^\s*0x[0-9a-fA-F]+\s*$/.test(source)) return [];

  let ast: unknown;
  try {
    ast = (parser as unknown as {
      parse: (src: string, opts?: Record<string, unknown>) => unknown;
    }).parse(source, { loc: false, tolerant: true });
  } catch {
    return [];
  }

  type Node = { type?: string; name?: string; visibility?: string; stateMutability?: string;
                parameters?: Node[]; returnParameters?: Node[]; typeName?: Node;
                baseTypeName?: Node; components?: Node[]; keyType?: Node; valueType?: Node };
  const items: AbiItem[] = [];

  const typeOf = (n: Node): { type: string; components?: AbiItem[] } => {
    const tn = n.typeName ?? {};
    const base = tn.typeName ?? tn.baseTypeName ?? tn;
    switch (tn.type) {
      case "ElementaryTypeName":
        return { type: String(tn.name ?? "bytes32") };
      case "UserDefinedTypeName":
        return { type: "address" };
      case "ArrayTypeName": {
        const inner = typeOf({ typeName: tn.baseTypeName });
        return { type: `${inner.type}[]` };
      }
      case "Mapping":
        return { type: "bytes32" };
      default:
        void base;
        return { type: "bytes32" };
    }
  };

  const param = (n: Node): { name?: string; type?: string; components?: AbiItem[] } => {
    const t = typeOf(n);
    return { name: String(n.name ?? ""), type: t.type };
  };

  const visit = (node: Node, depth = 0): void => {
    if (!node || typeof node !== "object" || depth > 12) return;
    if (node.type === "ContractDefinition") {
      // When a name is given, take only that contract; otherwise every one in the bundle.
      const match = !contractName || node.name === contractName;
      const body = (node as unknown as { subNodes?: Node[] }).subNodes ?? [];
      if (match) {
        for (const sub of body) {
          if (sub.type === "FunctionDefinition") {
            const vis = sub.visibility ?? "public";
            if (vis !== "public" && vis !== "external") continue;
            const name = sub.name;
            if (!name) continue; // constructor / fallback / receive: no ABI entry needed here
            const mut =
              sub.stateMutability ??
              ((sub as unknown as { isView?: boolean }).isView ? "view"
               : (sub as unknown as { isPure?: boolean }).isPure ? "pure" : "nonpayable");
            items.push({
              type: "function",
              name,
              inputs: (sub.parameters ?? []).map(param),
              outputs: (sub.returnParameters ?? []).map(param),
              stateMutability: mut,
            });
          } else if (sub.type === "StateVariableDeclaration") {
            // Public state variables expose an auto-generated getter. `constant` ones do too.
            const decl = sub as unknown as { variables?: Node[] };
            for (const v of decl.variables ?? []) {
              if ((v.visibility ?? "internal") !== "public" || !v.name) continue;
              items.push({
                type: "function",
                name: v.name,
                inputs: [],
                outputs: [param({ typeName: v.typeName })],
                stateMutability: "view",
              });
            }
          }
        }
      }
      return;
    }
    for (const key of Object.keys(node)) {
      const v = (node as Record<string, unknown>)[key];
      if (Array.isArray(v)) for (const c of v) visit(c as Node, depth + 1);
      else if (v && typeof v === "object") visit(v as Node, depth + 1);
    }
  };

  try {
    visit(ast as Node);
  } catch {
    return [];
  }

  // Deduplicate by name+arity; overloads keep distinct entries.
  const seen = new Set<string>();
  return items.filter((it) => {
    const k = `${it.name}/${(it.inputs ?? []).length}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/** Gather the target ABI, or null when nothing could be found. */
export async function gatherAbi(
  address: string,
  chain: number | string | null | undefined,
  opts?: { inventory?: Inventory | null; etherscanKey?: string; sourceBody?: string | null },
): Promise<GatheredAbi | null> {
  const chainId = normalizeChainId(chain);
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) return null;

  const sourcify = await fromSourcify(address, chainId);
  if (sourcify) return { abi: sourcify, source: "sourcify" };

  if (opts?.etherscanKey) {
    const etherscan = await fromEtherscan(address, chainId, opts.etherscanKey);
    if (etherscan) return { abi: etherscan, source: "etherscan" };
  }

  // Source-derived signatures ENRICH the heuristic; they do not replace it.
  //
  // Measured 2026-11-06 against four contracts from the archive page, parsed entries vs
  // heuristic entries: ZAMM 18/44, Stash 24/105, PoolManager 13/205, Blur Pool 0/34. The
  // source derivation is exact per entry but incomplete — these are multi-contract bundles
  // where the display label is not the Solidity contract name, and inheritance is not
  // followed, so base functions are missing. The heuristic reads the deployed bytecode's
  // selectors, so it covers the real callable surface.
  //
  // Replacing the heuristic with the parse would therefore LOSE callable functions and make
  // PoC ABI mismatches worse. Merging keeps coverage and upgrades precision: where a parsed
  // entry has the same name and arity, its parameter names, types and mutability win.
  const heuristic = heuristicAbiFromInventory(opts?.inventory);
  const fromSource = opts?.sourceBody
    ? abiFromSoliditySource(opts.sourceBody)
    : [];
  if (heuristic.length === 0 && fromSource.length === 0) return null;
  if (fromSource.length === 0) return { abi: heuristic, source: "heuristic" };
  if (heuristic.length === 0) return { abi: fromSource, source: "source" };

  // The heuristic names are QUALIFIED and its types are malformed. Measured from the
  // archive: {"name":"PoolManager.unlock","inputs":[{"name":"a0","type":"address
  // initialOwner"}]} — the type field carries the type AND the parameter name, and the
  // name carries the contract prefix. Neither can be fed to abi.encodeWithSignature, so
  // the stored ABI could not build call data for any function it described.
  //
  // Matching therefore keys on the UNQUALIFIED name and arity, and a match replaces the
  // whole entry with the parsed one, which has a plain name and clean types.
  const unqualified = (n: string) => n.slice(n.lastIndexOf(".") + 1);
  const exact = new Map<string, AbiItem>();
  for (const it of fromSource) {
    if (it.type !== "function" || !it.name) continue;
    exact.set(`${it.name}/${(it.inputs ?? []).length}`, it);
  }
  let upgraded = 0;
  const merged: AbiItem[] = heuristic.map((it) => {
    if (it.type !== "function" || !it.name) return it;
    const e = exact.get(`${unqualified(it.name)}/${(it.inputs ?? []).length}`);
    if (!e) return it;
    upgraded++;
    return e;
  });
  // Parsed entries the heuristic never saw (no selector resolved) are still real surface.
  const have = new Set(merged.map((it) => `${unqualified(String(it.name ?? ""))}/${(it.inputs ?? []).length}`));
  for (const it of fromSource) {
    if (it.type === "function" && it.name && !have.has(`${it.name}/${(it.inputs ?? []).length}`)) {
      merged.push(it);
      have.add(`${it.name}/${(it.inputs ?? []).length}`);
    }
  }
  return { abi: merged, source: upgraded > 0 ? "source" : "heuristic" };
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
