// src/lib/audit/poc-wrap.ts
//
// Turns a per-finding PoC snippet (an attack contract, not a runnable
// Foundry test) into a runnable Foundry test file, so the workbench
// Run button can actually execute it through the :8787 backend.
//
// The snippet is kept VERBATIM — the wrapper only prepends a missing
// SPDX / pragma / forge-std import and appends a `PoC` contract. The
// appended contract is named `PoC` because the :8787 backend runs
// `forge test --match-contract PoC` (termux-backend/server.mjs) —
// any other name (e.g. PocWrapTest) matches nothing and forge
// reports "no tests match the provided pattern".
//
// Semantics: a PASS means the wrapped exploit moved value on the fork
// (attacker balance up OR target balance down). That is a real
// value-moving exploit executed on fork, NOT a proof for non-value
// exploits (access-control, logic bugs, griefing, ...). Those still
// need the fallback templates (foundry/poc-fallbacks) or a full AI PoC.
//
// Parameter filling: the wrapper NEVER returns null just because the
// constructor or entry has parameters. Unknown-but-fillable params get
// defaults (fail-closed ONLY for genuinely unwrappable shapes: no
// contract defs, interfaces-only, or a param type outside the fill
// table):
//   address params are filled NAME-AWARE (Round 2 — Round 1's blanket
//   address -> target was wrong for Jer's Drain snippet, where the
//   second address is the payout recipient, not the victim):
//     name matches /(victim|target)/i            -> `target` (the fork target)
//     name is exactly `to`/`me`, ends with `_to`/`_me`,
//       or matches /(recipient|receiver|beneficiary|attacker|wallet|account)/i
//                                                -> the attacker contract:
//                                                   `address(attacker)`, or
//                                                   `payable(address(attacker))`
//                                                   when the type is `address payable`
//     otherwise (no name hint, e.g. `token`)      -> positional fallback:
//                                                   FIRST address param in the
//                                                   list -> `target`; any LATER
//                                                   address param -> attacker
//   A payable address param gets `payable(...)` wrapping (`payable(target)`
//   / `payable(address(attacker))`) — passing a plain address where
//   `address payable` is expected is a compile error.
//   uint / int of any size   -> `1 ether` (the value at stake)
//   bool                     -> `false`
//   string / bytes           -> `""`
//   fixed bytesN             -> `bytesN(0)`
//   dynamic arrays T[]       -> `new T[](0)` (element must itself be fillable)
//   anything else (structs, mappings, function types, fixed/nested
//   arrays, contract/enum types) -> return null (still fail-closed).
// A FAIL with filled defaults is informative (the guessed args may be
// wrong); an ERROR with no tests run is not. When defaults are used,
// WrappedPoc.note names them so the UI can show what was guessed.
//
// Round 4 — nulls are diagnostic, and a `PoC`-named attack contract is
// RENAMED, not rejected: `wrapPocSnippetWithReason` returns a one-line
// human-readable reason for every null, so a silent null can never
// again hide why the raw snippet was sent. And a snippet whose attack
// contract is itself named `PoC` (the most likely null path Round 3
// introduced) gets its `PoC` code tokens renamed to `PoCAttack`
// instead of returning null — `PoC` is reserved for the appended test
// contract, and the rename is named in WrappedPoc.note.
//
// Pure string builder. Zero imports. No Solidity parser — detection
// runs on a length-preserving comment/string-stripped copy so indices
// line up with the original snippet.

export type WrappedPoc = {
  /** Full runnable test file (snippet verbatim + appended Test contract). */
  testFile: string;
  /** Name of the attack contract found in the snippet. */
  attackContract: string;
  /** Entry function name called by the test. */
  entry: string;
  /** Null when no defaults were used; otherwise names the filled params. */
  note: string | null;
};

/** Result of {@link wrapPocSnippetWithReason}: the wrap plus, on null, why. */
export type WrapResult = {
  wrapped: WrappedPoc | null;
  /** One-line human-readable cause when `wrapped` is null, else null. */
  reason: string | null;
};

/** Entry-function names, first match in this order wins. */
const ENTRY_NAMES = [
  "attack",
  "exploit",
  "executeAttack",
  "execute",
  "seizeAndDrain",
  "seize",
  "poc",
  "hack",
  "run",
  "drain",
  "pwn",
  "go",
] as const;

/**
 * Length-preserving strip: comment and string contents become spaces,
 * newlines are kept, so indices in the result match the original source.
 */
function stripNonCode(src: string): string {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (c === "/" && n === "/") {
      while (i < src.length && src[i] !== "\n") {
        out += " ";
        i += 1;
      }
    } else if (c === "/" && n === "*") {
      out += "  ";
      i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) {
        out += src[i] === "\n" ? "\n" : " ";
        i += 1;
      }
      out += "  ";
      i += 2;
    } else if (c === '"' || c === "'") {
      const q = c;
      out += " ";
      i += 1;
      while (i < src.length && src[i] !== q) {
        if (src[i] === "\\") {
          out += "  ";
          i += 2;
          continue;
        }
        out += src[i] === "\n" ? "\n" : " ";
        i += 1;
      }
      out += " ";
      i += 1;
    } else {
      out += c;
      i += 1;
    }
  }
  return out;
}

/** Index of the `}` matching the `{` at openIdx, or -1 when unbalanced. */
function findMatchingBrace(text: string, openIdx: number): number {
  let depth = 0;
  for (let i = openIdx; i < text.length; i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

type ContractInfo = { name: string; body: string };

/** All `contract` definitions (not interface/library/abstract) in source order. */
function findContracts(stripped: string): ContractInfo[] {
  const out: ContractInfo[] = [];
  const re = /\bcontract\s+(\w+)\s*(?:is\s+[^{]*)?\{/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(stripped)) !== null) {
    // Exclude `abstract contract` — the word before `contract` is abstract.
    const before = stripped.slice(Math.max(0, m.index - 20), m.index);
    if (/\babstract\s*$/.test(before)) continue;
    const openIdx = m.index + m[0].length - 1;
    const closeIdx = findMatchingBrace(stripped, openIdx);
    if (closeIdx < 0) continue;
    out.push({ name: m[1], body: stripped.slice(openIdx + 1, closeIdx) });
  }
  return out;
}

type FnInfo = { name: string; params: string; headerAfterParams: string };

/** Scan from the `(` at openIdx to its matching `)`, or -1 when unbalanced. */
function findMatchingParen(text: string, openIdx: number): number {
  let depth = 0;
  for (let i = openIdx; i < text.length; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function findFunctions(body: string): FnInfo[] {
  const out: FnInfo[] = [];
  const re = /function\s+(\w+)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    // Balanced-paren scan: the param list may itself contain parens
    // (e.g. mapping(address => uint256)), so `[^)]*` would truncate it.
    const openIdx = m.index + m[0].length - 1;
    const closeIdx = findMatchingParen(body, openIdx);
    if (closeIdx < 0) continue;
    const params = body.slice(openIdx + 1, closeIdx);
    const rest = body.slice(closeIdx + 1);
    const headerEnd = rest.search(/[{;]/);
    const headerAfterParams = headerEnd < 0 ? rest : rest.slice(0, headerEnd);
    out.push({ name: m[1], params, headerAfterParams });
  }
  return out;
}

/** Raw constructor parameter list of the first constructor, or null when absent. */
function findConstructorParams(body: string): string | null {
  const m = /constructor\s*\(/.exec(body);
  if (!m) return null;
  const openIdx = m.index + m[0].length - 1;
  const closeIdx = findMatchingParen(body, openIdx);
  if (closeIdx < 0) return null;
  return body.slice(openIdx + 1, closeIdx);
}

function splitTopLevelArgs(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of text) {
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    if (ch === "," && depth === 0) {
      out.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  out.push(cur);
  return out;
}

/**
 * Split one parameter string into its type + name. The type is
 * everything before the name token, so parenthesized types stay whole
 * (e.g. `mapping(address => uint256) m` -> type
 * `mapping(address => uint256)`, name `m`). A trailing data-location
 * keyword with no name (`string memory`) is dropped from the type;
 * `payable` stays part of the type for `address payable`.
 * Returns type null only for an empty parameter string.
 */
function splitParam(param: string): { type: string | null; name: string | null } {
  const tokens = param.trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return { type: null, name: null };
  let name: string | null = null;
  let typeTokens = tokens;
  const last = tokens[tokens.length - 1];
  if (tokens.length >= 2 && last !== "memory" && last !== "calldata" && last !== "storage" && last !== "payable") {
    name = last;
    typeTokens = tokens.slice(0, -1);
  }
  // Drop a trailing data-location keyword that is not part of the type.
  while (
    typeTokens.length > 1 &&
    ["memory", "calldata", "storage"].includes(typeTokens[typeTokens.length - 1])
  ) {
    typeTokens = typeTokens.slice(0, -1);
  }
  return { type: typeTokens.join(" "), name };
}

/** Fill for a scalar (non-array) type, or null when outside the fill table. */
function fillForScalar(type: string): string | null {
  if (type === "address" || type === "address payable") return "target";
  if (/^u?int(\d+)?$/.test(type)) return "1 ether";
  if (type === "bool") return "false";
  if (type === "string" || type === "bytes") return '""';
  if (/^bytes\d+$/.test(type)) return `${type}(0)`;
  return null;
}

/** Fill for any type in the fill table (scalars + dynamic arrays), or null. */
function fillForType(type: string): string | null {
  const scalar = fillForScalar(type);
  if (scalar !== null) return scalar;
  if (type.endsWith("[]")) {
    const elem = type.slice(0, -2);
    if (elem.includes("[") || elem.includes("]")) return null; // nested arrays
    if (fillForScalar(elem) === null) return null; // struct/contract/enum element
    return `new ${elem}[](0)`;
  }
  return null;
}

/**
 * Fill one parameter list. Returns the filled arg list + the type list
 * (for the note), or the offending type when any param is unfillable
 * (fail closed — the caller turns it into a diagnostic reason).
 */
function fillParamList(paramList: string): { args: string; types: string } | { badType: string } {
  const trimmed = paramList.trim();
  if (!trimmed) return { args: "", types: "" };
  const params = splitTopLevelArgs(trimmed)
    .map((p) => p.trim())
    .filter(Boolean);
  const fills: string[] = [];
  const types: string[] = [];
  let addressCount = 0;
  for (const p of params) {
    const { type, name } = splitParam(p);
    if (type === null) return { badType: "(empty)" };
    let fill: string | null;
    if (type === "address" || type === "address payable") {
      fill = fillForAddress(name, type, addressCount === 0);
      addressCount++;
    } else {
      fill = fillForType(type);
    }
    if (fill === null) return { badType: type };
    fills.push(fill);
    types.push(type);
  }
  return { args: fills.join(", "), types: types.join(", ") };
}

/**
 * Fill for an address param, honouring name hints. `isFirstAddress` =
 * this is the first address param in its list (positional fallback).
 * A payable param gets `payable(...)` wrapping — a plain address is
 * not implicitly convertible to `address payable`.
 */
function fillForAddress(name: string | null, type: string, isFirstAddress: boolean): string {
  const wrapPayable = (inner: string) => (type === "address payable" ? `payable(${inner})` : inner);
  if (name !== null) {
    if (/victim|target/i.test(name)) return wrapPayable("target");
    if (
      /^to$/i.test(name) ||
      /^me$/i.test(name) ||
      /_to$/i.test(name) ||
      /_me$/i.test(name) ||
      /recipient|receiver|beneficiary|attacker|wallet|account/i.test(name)
    ) {
      return wrapPayable("address(attacker)");
    }
  }
  // No name hint: positional fallback.
  return isFirstAddress ? wrapPayable("target") : wrapPayable("address(attacker)");
}

/**
 * Rename every `PoC` code token in `snippet` to `PoCAttack`, returning
 * the renamed snippet. Matches are found on the length-preserving
 * comment/string-stripped copy (so comments and string literals are
 * never touched) and applied to the verbatim snippet RIGHT-TO-LEFT so
 * earlier indices stay valid.
 */
function renamePoCToPoCAttack(snippet: string, stripped: string): string {
  const re = /\bPoC\b/g;
  const indices: number[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(stripped)) !== null) indices.push(m.index);
  let out = snippet;
  for (let i = indices.length - 1; i >= 0; i--) {
    const idx = indices[i];
    out = out.slice(0, idx) + "PoCAttack" + out.slice(idx + 3);
  }
  return out;
}

/**
 * Wrap a PoC snippet into a runnable Foundry test file, with a
 * diagnostic reason on failure. `wrapped` is null only for genuinely
 * unwrappable shapes (fail closed — the caller falls back to running
 * the raw snippet, which errors with a clear note): no contract defs,
 * interfaces-only, or a param type outside the fill table. A snippet
 * whose attack contract is named `PoC` is RENAMED to `PoCAttack`
 * (see below), never rejected.
 * Every null carries a one-line reason — never a silent null.
 */
export function wrapPocSnippetWithReason(snippet: string): WrapResult {
  const fail = (reason: string): WrapResult => ({ wrapped: null, reason });
  if (!snippet || !snippet.trim()) return fail("empty snippet");
  let stripped = stripNonCode(snippet);
  // Pass-through: already a runnable Foundry test (contract inherits
  // Test and defines a test_ function). Return it unchanged — this
  // runs FIRST, so a Test already named PoC is never renamed.
  const isTest = /\bcontract\s+\w+\s+is\s+[^{]*\bTest\b/.test(stripped);
  const hasTestFn = /function\s+test_\w*\s*\(/.test(stripped);
  if (isTest && hasTestFn) {
    return {
      wrapped: { testFile: snippet, attackContract: "<existing>", entry: "<existing>", note: null },
      reason: null,
    };
  }
  // `PoC` is reserved for the appended test contract. If the snippet
  // defines a (non-Test) contract named `PoC`, rename its `PoC` code
  // tokens to `PoCAttack` instead of returning null.
  let working = snippet;
  let renamed = false;
  if (/\bPoC\b/.test(stripped)) {
    if (/\bPoCAttack\b/.test(stripped)) {
      return fail("snippet defines contracts named both PoC and PoCAttack; cannot rename safely");
    }
    working = renamePoCToPoCAttack(snippet, stripped);
    stripped = stripNonCode(working);
    renamed = true;
  }
  const contracts = findContracts(stripped);
  if (contracts.length === 0) {
    if (/\binterface\s+\w+/.test(stripped)) {
      return fail("no contract definitions found (interfaces only — the snippet defines no contract)");
    }
    return fail("no contract definitions found");
  }
  // Attack contract = first contract (source order) with the
  // highest-priority entry function.
  let attack: ContractInfo | null = null;
  let entry: FnInfo | null = null;
  for (const entryName of ENTRY_NAMES) {
    for (const c of contracts) {
      const fn = findFunctions(c.body).find((f) => f.name === entryName);
      if (fn) {
        attack = c;
        entry = fn;
        break;
      }
    }
    if (attack) break;
  }
  if (!attack || !entry) {
    const prefixes = ["attack", "exploit", "execute", "drain", "seize", "pwn", "take"];
    for (const prefix of prefixes) {
      for (const c of contracts) {
        const fn = findFunctions(c.body).find((f) => f.name.toLowerCase().startsWith(prefix));
        if (fn) {
          attack = c;
          entry = fn;
          break;
        }
      }
      if (attack) break;
    }
  }
  if (!attack || !entry) {
    return fail(
      "no entry function found (looked for attack/exploit/executeAttack/execute/seizeAndDrain/seize/poc/hack/run/drain/pwn/go, or a name starting with attack/exploit/execute/drain/seize/pwn/take)",
    );
  }
  // Fill constructor + entry params from the fill table (never null
  // just for having params — a FAIL with guessed args is informative).
  const ctorFilled = fillParamList(findConstructorParams(attack.body) ?? "");
  if ("badType" in ctorFilled) {
    return fail(`constructor param type ${ctorFilled.badType} is not fillable`);
  }
  const entryFilled = fillParamList(entry.params);
  if ("badType" in entryFilled) {
    return fail(`entry param type ${entryFilled.badType} is not fillable`);
  }
  const defaultsParts: string[] = [];
  if (ctorFilled.types) defaultsParts.push(`constructor (${ctorFilled.types}) -> (${ctorFilled.args})`);
  if (entryFilled.types) defaultsParts.push(`entry ${entry.name}(${entryFilled.types}) -> ${entry.name}(${entryFilled.args})`);
  const noteBits: string[] = [];
  if (renamed) noteBits.push("renamed attack contract PoC -> PoCAttack (PoC is reserved for the test contract)");
  if (defaultsParts.length) noteBits.push(`Wrapped with defaults: ${defaultsParts.join("; ")}`);
  const note = noteBits.length ? noteBits.join("; ") : null;
  const payable = /\bpayable\b/.test(entry.headerAfterParams);
  const call = `attacker.${entry.name}${payable ? "{value: 1 ether}" : ""}(${entryFilled.args});`;
  const deploy = `new ${attack.name}(${ctorFilled.args})`;
  const prefix: string[] = [];
  if (!/SPDX-License-Identifier/.test(working)) prefix.push("// SPDX-License-Identifier: MIT");
  if (!/pragma\s+solidity/.test(working)) prefix.push("pragma solidity ^0.8.0;");
  if (!/forge-std\/Test\.sol/.test(working)) prefix.push('import "forge-std/Test.sol";');
  const header = prefix.length ? prefix.join("\n") + "\n" : "";
  const testContract = [
    "",
    "contract PoC is Test {",
    "    function testPoc() public {",
    '        vm.createSelectFork(vm.envString("POC_RPC_URL"));',
    '        address target = vm.envAddress("POC_TARGET");',
    `        ${attack.name} attacker = ${deploy};`,
    "        vm.deal(address(this), 10 ether);",
    "        vm.deal(address(attacker), 10 ether);",
    "        uint256 attackerBefore = address(attacker).balance;",
    "        uint256 targetBefore = target.balance;",
    `        ${call}`,
    '        assertTrue(address(attacker).balance > attackerBefore || target.balance < targetBefore, "no value moved");',
    "    }",
    "}",
    "",
  ].join("\n");
  return {
    wrapped: { testFile: header + working + testContract, attackContract: attack.name, entry: entry.name, note },
    reason: null,
  };
}

/** Thin wrapper for callers that only need the wrap (or null). */
export function wrapPocSnippet(snippet: string): WrappedPoc | null {
  return wrapPocSnippetWithReason(snippet).wrapped;
}
