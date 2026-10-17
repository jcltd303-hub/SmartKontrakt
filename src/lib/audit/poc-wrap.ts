// src/lib/audit/poc-wrap.ts
//
// Turns a per-finding PoC snippet (an attack contract, not a runnable
// Foundry test) into a runnable Foundry test file, so the workbench
// Run button can actually execute it through the :8787 backend.
//
// The snippet is kept VERBATIM — the wrapper only prepends a missing
// SPDX / pragma / forge-std import and appends a PocWrapTest contract.
//
// Semantics: a PASS means the wrapped exploit moved value on the fork
// (attacker balance up OR target balance down). That is a real
// value-moving exploit executed on fork, NOT a proof for non-value
// exploits (access-control, logic bugs, griefing, ...). Those still
// need the fallback templates (foundry/poc-fallbacks) or a full AI PoC.
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
};

/** Entry-function names, first match in this order wins. */
const ENTRY_NAMES = ["attack", "exploit", "poc", "hack", "run"] as const;

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

function findFunctions(body: string): FnInfo[] {
  const out: FnInfo[] = [];
  const re = /function\s+(\w+)\s*\(([^)]*)\)\s*([^{;]*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    out.push({ name: m[1], params: m[2], headerAfterParams: m[3] });
  }
  return out;
}

/** Raw constructor parameter list of the first constructor, or null when absent. */
function findConstructorParams(body: string): string | null {
  const m = /constructor\s*\(([^)]*)\)/.exec(body);
  return m ? m[1] : null;
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
 * Deploy argument for the attack contract constructor.
 * Returns "" for `new X()`, "target" for `new X(target)`, null for any
 * unsupported shape (fail closed).
 */
function constructorDeployArg(ctorParams: string | null): string | null {
  if (ctorParams === null) return ""; // no constructor -> new X()
  const trimmed = ctorParams.trim();
  if (!trimmed) return ""; // constructor() -> new X()
  const params = splitTopLevelArgs(trimmed)
    .map((p) => p.trim())
    .filter(Boolean);
  if (params.length !== 1) return null;
  const tokens = params[0].split(/\s+/);
  const isAddress =
    tokens[0] === "address" && (tokens.length === 2 || (tokens.length === 3 && tokens[1] === "payable"));
  if (!isAddress) return null;
  return "target";
}

/**
 * Wrap a PoC snippet into a runnable Foundry test file.
 * Returns null for unsupported shapes (fail closed — the caller falls
 * back to running the raw snippet, which errors with a clear note).
 */
export function wrapPocSnippet(snippet: string): WrappedPoc | null {
  if (!snippet || !snippet.trim()) return null;
  const stripped = stripNonCode(snippet);
  // Pass-through: already a runnable Foundry test (contract inherits
  // Test and defines a test_ function). Return it unchanged.
  const isTest = /\bcontract\s+\w+\s+is\s+[^{]*\bTest\b/.test(stripped);
  const hasTestFn = /function\s+test_\w*\s*\(/.test(stripped);
  if (isTest && hasTestFn) {
    return { testFile: snippet, attackContract: "<existing>", entry: "<existing>" };
  }
  const contracts = findContracts(stripped);
  if (contracts.length === 0) return null;
  // The appended test contract would collide with this name.
  if (contracts.some((c) => c.name === "PocWrapTest")) return null;
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
  if (!attack || !entry) return null;
  // Entry must take 0 params.
  if (entry.params.trim() !== "") return null;
  const deployArg = constructorDeployArg(findConstructorParams(attack.body));
  if (deployArg === null) return null;
  const payable = /\bpayable\b/.test(entry.headerAfterParams);
  const call = `attacker.${entry.name}${payable ? "{value: 1 ether}" : ""}();`;
  const deploy = deployArg === "" ? `new ${attack.name}()` : `new ${attack.name}(target)`;
  const prefix: string[] = [];
  if (!/SPDX-License-Identifier/.test(snippet)) prefix.push("// SPDX-License-Identifier: MIT");
  if (!/pragma\s+solidity/.test(snippet)) prefix.push("pragma solidity ^0.8.0;");
  if (!/forge-std\/Test\.sol/.test(snippet)) prefix.push('import "forge-std/Test.sol";');
  const header = prefix.length ? prefix.join("\n") + "\n" : "";
  const testContract = [
    "",
    "contract PocWrapTest is Test {",
    "    function test_poc() public {",
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
  return { testFile: header + snippet + testContract, attackContract: attack.name, entry: entry.name };
}
