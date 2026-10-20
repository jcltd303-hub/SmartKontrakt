/**
 * SmartPoC Bug-Context Extraction (BCE).
 *
 * Implements §3.2 of arXiv:2511.12993. Given the contract source and a static
 * finding, BCE produces a *compact, semantically rich slice* of the contract —
 * just the functions needed to reproduce the bug — instead of feeding the LLM
 * the whole file (noisy input → long-context degradation and hallucination).
 *
 * The paper expands the key function along four motifs (Figure 3):
 *
 *   semantic links
 *     (a) inverse operations        deposit/withdraw, mint/burn, stake/unstake …
 *     (b) state-coupled operations  functions that read/update the same storage
 *   structural links
 *     (c) modifier-based control    modifiers that gate the key function
 *     (d) wrapper function flow     public entry -> underscore internal
 *
 * plus the call graph one hop in each direction, and the constructors /
 * initializers of the contracts that define the sliced functions.
 *
 * This module is the deterministic core: it parses the source with the app's own
 * Solidity parser (`../model.ts`), so no Slither dependency is needed. An
 * optional `inferSemanticLinks` callback lets the caller refine (a)/(b) with an
 * LLM, exactly as the paper does — but the slice is always produced even when
 * the callback is absent or fails.
 */

import { parseSource } from "../model.ts";
import { stripNonCode } from "./text.ts";
import type { PocTarget } from "./sanitize.ts";

export type BceFinding = {
  title: string;
  detector: string;
  severity: string;
  summary: string;
  locationFn?: string | null;
};

export type BceInput = {
  /** Contract source (or a verified source bundle). */
  body: string;
  findings: BceFinding[];
  /**
   * Optional LLM step: given the canonical function list and the key functions,
   * return the names of inverse / state-coupled counterparts (paper §3.2.2).
   */
  inferSemanticLinks?: (args: {
    functions: { name: string; signature: string }[];
    keyFunctions: string[];
  }) => Promise<string[]>;
};

export type BugContext = {
  /** The compact source slice handed to the PoC generator. */
  context: string;
  /** Function names included in the slice, in inclusion order. */
  functions: string[];
  /** Build metadata (pragma / compiler) the paper requires for compilation. */
  buildMetadata: string;
  /** Human-readable notes about how the slice was assembled. */
  notes: string[];
};

/**
 * Build a sanitizer `PocTarget` (contract name, compiler, function signatures)
 * directly from contract source — used where the report inventory is not at
 * hand (e.g. the pipeline worker).
 */
export function pocTargetFromSource(
  body: string,
  contractName: string,
  compilerVersion?: string | null,
): PocTarget {
  const model = parseSource(body);
  const sigs = new Set<string>();
  for (const contract of model.contracts) {
    for (const fn of contract.functions) {
      if (!fn.name || fn.isConstructor || fn.isFallback || fn.isReceive) continue;
      sigs.add(`${fn.name}(${fn.params.map((p) => normType(p.typeName)).join(",")})`);
    }
  }
  return { contractName, compilerVersion: compilerVersion ?? null, functionSignatures: [...sigs] };
}

type FnEntry = {
  contract: string;
  name: string;
  signature: string;
  source: string;
  line: number;
  modifiers: string[];
  isConstructor: boolean;
  isInitializer: boolean;
  visibility: string;
  stateRefs: string[];
};

const INVERSE_PAIRS: [string, string][] = [
  ["deposit", "withdraw"],
  ["mint", "burn"],
  ["mint", "redeem"],
  ["deposit", "redeem"],
  ["stake", "unstake"],
  ["lock", "unlock"],
  ["add", "remove"],
  ["set", "get"],
  ["increase", "decrease"],
  ["buy", "sell"],
  ["borrow", "repay"],
  ["push", "pop"],
  ["open", "close"],
  ["enter", "exit"],
  ["supply", "withdraw"],
  ["join", "exit"],
  ["grant", "revoke"],
  ["pause", "unpause"],
];

/** Bare function name from a finding location like "withdraw()" or "Vault.withdraw". */
function bareName(location: string | null | undefined): string | null {
  if (!location) return null;
  const cleaned = location.replace(/\(.*$/, "").trim();
  const tail = cleaned.includes(".") ? cleaned.slice(cleaned.lastIndexOf(".") + 1) : cleaned;
  return /^[A-Za-z_]\w*$/.test(tail) ? tail : null;
}

function normType(type: string): string {
  return type.toLowerCase().replace(/\s+/g, "").replace(/payable$/, "");
}

/** Names of state variables referenced in a function body. */
function stateRefsIn(source: string, stateNames: string[]): string[] {
  const stripped = stripNonCode(source);
  return stateNames.filter((name) => new RegExp(`\\b${name}\\b`).test(stripped));
}

/**
 * Build the compact bug-context slice. Deterministic; the optional LLM callback
 * only *adds* semantic counterparts.
 */
export async function extractBugContext(input: BceInput): Promise<BugContext> {
  const notes: string[] = [];
  const model = parseSource(input.body);
  const contractNames = model.contracts.map((c) => c.name);

  // 1. Canonical function set (paper: "run slither to recover the call graph and
  //    a canonical function set"). We use the app's own parser instead.
  const entries: FnEntry[] = [];
  for (const contract of model.contracts) {
    const stateNames = contract.stateVars.map((v) => v.name);
    for (const fn of contract.functions) {
      entries.push({
        contract: contract.name,
        name: fn.name,
        signature: `${fn.name}(${fn.params.map((p) => normType(p.typeName)).join(",")})`,
        source: fn.source,
        line: fn.line,
        modifiers: fn.modifiers,
        isConstructor: fn.isConstructor,
        isInitializer: /^_?initialize\d*$/i.test(fn.name),
        visibility: fn.visibility,
        stateRefs: stateRefsIn(fn.source, stateNames),
      });
    }
  }
  const byName = new Map<string, FnEntry[]>();
  for (const e of entries) {
    const list = byName.get(e.name) ?? [];
    list.push(e);
    byName.set(e.name, list);
  }

  const included = new Map<string, FnEntry>(); // key: contract:name:signature
  const add = (e: FnEntry): boolean => {
    const key = `${e.contract}:${e.signature}`;
    if (included.has(key)) return false;
    included.set(key, e);
    return true;
  };

  // 2. Seed from the finding's key functions, filtered against the canonical set
  //    (paper: "discard non-existent symbols").
  const keyNames = new Set<string>();
  for (const finding of input.findings) {
    const name = bareName(finding.locationFn) ?? bareName(finding.title);
    if (!name) continue;
    if (!byName.has(name)) {
      notes.push(`finding "${finding.title}" named \`${name}\`, which is not in the source — discarded`);
      continue;
    }
    keyNames.add(name);
    for (const e of byName.get(name)!) add(e);
  }
  // Fallback: if no finding named a real function, seed with every state-mutating
  // external function (better a wider slice than an empty one).
  if (keyNames.size === 0) {
    for (const e of entries) {
      if (!e.isConstructor && e.visibility !== "internal" && e.visibility !== "private") add(e);
    }
    notes.push("no finding named a resolvable function; seeded with all external functions");
  }

  // 3. Semantic links — LLM when provided, deterministic heuristic otherwise.
  const semantic = new Set<string>();
  if (input.inferSemanticLinks) {
    try {
      const inferred = await input.inferSemanticLinks({
        functions: entries.map((e) => ({ name: e.name, signature: e.signature })),
        keyFunctions: [...keyNames],
      });
      for (const name of inferred) if (byName.has(name)) semantic.add(name);
      notes.push(`LLM inferred ${semantic.size} semantic counterpart(s)`);
    } catch (err) {
      notes.push(`semantic-link inference failed (${err instanceof Error ? err.message : String(err)}); using heuristic`);
    }
  }
  if (semantic.size === 0) {
    for (const name of keyNames) {
      for (const [a, b] of INVERSE_PAIRS) {
        if (name.toLowerCase().includes(a) && byName.has(b)) semantic.add(b);
        if (name.toLowerCase().includes(b) && byName.has(a)) semantic.add(a);
      }
    }
    // State-coupled: any function touching a state var a key function touches.
    const keyStateRefs = new Set<string>();
    for (const name of keyNames) for (const e of byName.get(name)!) for (const s of e.stateRefs) keyStateRefs.add(s);
    for (const e of entries) {
      if (e.stateRefs.some((s) => keyStateRefs.has(s))) semantic.add(e.name);
    }
    if (semantic.size) notes.push(`heuristic semantic links: ${[...semantic].join(", ")}`);
  }
  for (const name of semantic) for (const e of byName.get(name) ?? []) add(e);

  // 4. Structural links: call graph ±1 hop + wrapper flow + modifiers.
  const names = new Set(byName.keys());
  const calleesOf = (e: FnEntry): string[] => {
    const stripped = stripNonCode(e.source);
    const out: string[] = [];
    for (const n of names) {
      if (n === e.name) continue;
      if (new RegExp(`\\b${n}\\s*\\(`).test(stripped)) out.push(n);
    }
    return out;
  };
  const callersOf = (name: string): FnEntry[] =>
    entries.filter((e) => e.name !== name && new RegExp(`\\b${name}\\s*\\(`).test(stripNonCode(e.source)));

  for (const e of [...included.values()]) {
    for (const callee of calleesOf(e)) for (const c of byName.get(callee) ?? []) add(c);
    for (const caller of callersOf(e.name)) add(caller);
    // Wrapper flow: underscore-prefixed internals reached from this function.
    for (const callee of calleesOf(e)) {
      if (callee.startsWith("_")) for (const c of byName.get(callee) ?? []) add(c);
    }
  }

  // 5. Constructors / initializers of the contracts that define the slice.
  const contractsInSlice = new Set([...included.values()].map((e) => e.contract));
  for (const e of entries) {
    if (contractsInSlice.has(e.contract) && (e.isConstructor || e.isInitializer)) add(e);
  }

  // 6. Modifiers referenced by the sliced functions (preserve access-control).
  const modifierBlocks: string[] = [];
  const modifierNames = new Set<string>();
  for (const e of included.values()) for (const m of e.modifiers) modifierNames.add(m);
  for (const contract of model.contracts) {
    for (const mod of contract.modifiers) {
      if (modifierNames.has(mod.name)) modifierBlocks.push(mod.source.trim());
    }
  }

  // 7. Assemble, dedup, ordered by contract then line.
  const ordered = [...included.values()].sort(
    (a, b) => (a.contract === b.contract ? a.line - b.line : a.contract.localeCompare(b.contract)),
  );
  const buildMetadata = [
    model.pragma ? `pragma ${model.pragma}` : "pragma: unknown",
    model.versionFloor !== null ? `compiler floor ${model.versionFloor}` : "compiler: unknown",
    `contracts: ${contractNames.join(", ") || "unknown"}`,
  ].join(" | ");

  const header = [
    `// SmartPoC bug-context slice — ${ordered.length} function(s) from ${contractsInSlice.size} contract(s).`,
    `// Build metadata: ${buildMetadata}`,
    `// Functions: ${ordered.map((e) => e.signature).join(", ")}`,
  ].join("\n");

  const context = [header, ...ordered.map((e) => e.source.trim()), ...modifierBlocks].join("\n\n");

  return {
    context,
    functions: ordered.map((e) => e.signature),
    buildMetadata,
    notes,
  };
}
