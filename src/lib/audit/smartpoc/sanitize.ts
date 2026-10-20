/**
 * SmartPoC pre-execution sanitizer.
 *
 * Implements the "Pre-execution Sanitizer" of the SmartPoC GRE-Engine
 * (arXiv:2511.12993 §3.3.2). The LLM produces a Foundry test *draft*; before it
 * is compiled or run we apply deterministic, build-time fixes that the paper
 * prescribes, confined entirely to the generated PoC (the original project is
 * never touched):
 *
 *   1. Align `pragma solidity` with the target's compiler version, and enable
 *      `abicoder v2` for legacy (<0.8) compilers.
 *   2. Guarantee the `forge-std/Test.sol` import the harness needs.
 *   3. Remove duplicate / conflicting definitions — a PoC that re-declares the
 *      target's own functions validates the LLM's rewrite instead of the
 *      original contract, the "spurious pass" failure mode of §1(ii).
 *
 * Pure string work: no compiler, no network, no imports. Unit-tested in
 * `sanitize.test.ts`.
 */

import { stripNonCode, splitTopLevel, matchBrace, matchParen } from "./text.ts";

export type PocTarget = {
  /** Target contract name, e.g. "Vault". */
  contractName: string;
  /** Solidity compiler version string, e.g. "0.8.24", when known. */
  compilerVersion?: string | null;
  /** Signatures the target declares, e.g. ["withdraw(uint256)", "owner()"]. */
  functionSignatures: string[];
};

export type SanitizeResult = {
  code: string;
  /** Human-readable list of every deterministic edit applied. */
  notes: string[];
};

/** Solidity < 0.8 needs `pragma abicoder v2` for ABIEncoderV2 features. */
const LEGACY_ABICODER_BELOW = 8;
const FALLBACK_PRAGMA = "^0.8.24";
const FORGE_STD_IMPORT = 'import {Test, console} from "forge-std/Test.sol";';

/** Parse "0.8.24" / "^0.8.24" / ">=0.8.0" into [major, minor, patch] | null. */
function parseVersion(value: string | null | undefined): [number, number, number] | null {
  if (!value) return null;
  const m = value.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

/**
 * Normalize a Solidity type for signature comparison: lowercase, no spaces,
 * and `address payable` folded to `address` (the ABI type is the same).
 */
function normalizeType(type: string): string {
  return type.toLowerCase().replace(/\s+/g, "").replace(/payable$/, "");
}

/** "uint256 amount, address to" -> "uint256,address". */
function normalizeParams(params: string): string {
  const parts = splitTopLevel(params);
  return parts
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => {
      // Drop a trailing parameter name: "uint256 amount" -> "uint256".
      const tokens = p.split(/\s+/);
      const type = tokens.length > 1 ? tokens.slice(0, -1).join("") : tokens[0];
      return normalizeType(type);
    })
    .join(",");
}

type Container = {
  kind: "contract" | "interface" | "library";
  name: string;
  /** Offset of the `{` that opens the container body. */
  open: number;
  /** Offset of the matching `}`. */
  close: number;
};

/**
 * A PoC legitimately defines attacker/helper contracts that may reuse a
 * function NAME from the target (e.g. an attacker's own `withdraw`). Only a
 * container that is NOT one of these has its target-matching functions treated
 * as an unintended rewrite of the target and removed.
 */
const ATTACKER_CONTAINER = /(attack|exploit|malicious|hacker|adversary|helper|reentran)/i;

/** Top-level `contract|interface|library` definitions and their body ranges. */
function findContainers(stripped: string): Container[] {
  const out: Container[] = [];
  const re = /\b(contract|interface|library)\s+([A-Za-z_]\w*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(stripped)) !== null) {
    const kind = m[1] as Container["kind"];
    const name = m[2];
    const brace = stripped.indexOf("{", m.index);
    if (brace === -1) continue;
    const close = matchBrace(stripped, brace);
    if (close === -1) continue;
    out.push({ kind, name, open: brace, close });
    re.lastIndex = close;
  }
  return out;
}

type FnDecl = {
  /** `function` keyword offset. */
  start: number;
  /** Offset just past the declaration's body `}` or `;`. */
  end: number;
  signature: string;
};

/** Function definitions directly inside a container body. */
function findFunctions(stripped: string, container: Container): FnDecl[] {
  const out: FnDecl[] = [];
  const re = /\bfunction\s+([A-Za-z_]\w*)\s*\(/g;
  re.lastIndex = container.open;
  let m: RegExpExecArray | null;
  while ((m = re.exec(stripped)) !== null) {
    if (m.index >= container.close) break;
    const openParen = m.index + m[0].length - 1;
    const closeParen = matchParen(stripped, openParen);
    if (closeParen === -1) continue;
    const params = stripped.slice(openParen + 1, closeParen);
    const signature = `${m[1]}(${normalizeParams(params)})`;
    // The declaration ends at its body `}` or a `;` (abstract/interface).
    const brace = stripped.indexOf("{", closeParen);
    const semi = stripped.indexOf(";", closeParen);
    let end: number;
    if (brace !== -1 && (semi === -1 || brace < semi)) {
      const bodyEnd = matchBrace(stripped, brace);
      end = bodyEnd === -1 ? closeParen + 1 : bodyEnd + 1;
    } else if (semi !== -1) {
      end = semi + 1;
    } else {
      end = closeParen + 1;
    }
    out.push({ start: m.index, end, signature });
  }
  return out;
}

/**
 * Remove ranges [start,end) from the ORIGINAL source, replacing each with a
 * one-line comment so line numbers stay roughly stable.
 */
function removeRanges(src: string, ranges: [number, number][], label: string): string {
  if (!ranges.length) return src;
  const sorted = [...ranges].sort((a, b) => a[0] - b[0]);
  let out = "";
  let cursor = 0;
  for (const [start, end] of sorted) {
    if (start < cursor) continue; // overlap — already removed
    out += src.slice(cursor, start);
    out += `/* ${label}: removed by pre-execution sanitizer */`;
    cursor = end;
  }
  out += src.slice(cursor);
  return out;
}

/**
 * Deterministic sanitizer. Returns the repaired draft plus a note per edit.
 */
export function sanitizePocDraft(draft: string, target: PocTarget): SanitizeResult {
  const notes: string[] = [];
  let code = draft;

  // 1. SPDX header.
  if (!/SPDX-License-Identifier/.test(code)) {
    code = `// SPDX-License-Identifier: MIT\n${code}`;
    notes.push("added SPDX-License-Identifier");
  }

  // 2. Pragma: align with the target's compiler version.
  const version = parseVersion(target.compilerVersion);
  const desiredPragma = version
    ? `pragma solidity ${version[0]}.${version[1]}.${version[2]};`
    : null;
  if (desiredPragma) {
    if (/pragma\s+solidity\s+[^;]+;/.test(code)) {
      code = code.replace(/pragma\s+solidity\s+[^;]+;/, desiredPragma);
      notes.push(`aligned pragma to ${version!.join(".")} (target compiler)`);
    } else {
      code = `${code.replace(/\n?$/, "\n")}\n${desiredPragma}\n`;
      notes.push(`inserted pragma ${version!.join(".")} (target compiler)`);
    }
  } else if (!/pragma\s+solidity/.test(code)) {
    code = `${code.replace(/\n?$/, "\n")}\npragma solidity ${FALLBACK_PRAGMA};\n`;
    notes.push(`inserted fallback pragma ${FALLBACK_PRAGMA} (no target compiler version)`);
  }

  // 3. abicoder v2 for legacy compilers (paper: "enable ABIEncoderV2").
  if (version && version[0] < LEGACY_ABICODER_BELOW && !/abicoder\s+v2/.test(code)) {
    code = code.replace(/(pragma\s+solidity\s+[^;]+;)/, "$1\npragma abicoder v2;");
    notes.push("added `pragma abicoder v2` (compiler < 0.8)");
  }

  // 4. forge-std import.
  if (!/forge-std\/Test\.sol/.test(code)) {
    const anchor = code.match(/pragma\s+solidity\s+[^;]+;/);
    if (anchor && anchor.index !== undefined) {
      const at = anchor.index + anchor[0].length;
      code = `${code.slice(0, at)}\n${FORGE_STD_IMPORT}${code.slice(at)}`;
    } else {
      code = `${FORGE_STD_IMPORT}\n${code}`;
    }
    notes.push("added forge-std/Test.sol import");
  }

  // 5. Remove duplicate / conflicting function definitions.
  const targetSigs = new Set(target.functionSignatures.map(normalizeSignature));
  const stripped = stripNonCode(code);
  const containers = findContainers(stripped);
  const removals: [number, number][] = [];
  for (const container of containers) {
    const fns = findFunctions(stripped, container);
    const seen = new Set<string>();
    for (const fn of fns) {
      const sig = normalizeSignature(fn.signature);
      // (a) The PoC must not re-implement the target's own functions — unless
      // the container is clearly an attacker/helper harness, whose same-named
      // functions are legitimate.
      if (container.kind === "contract" && targetSigs.has(sig) && !ATTACKER_CONTAINER.test(container.name)) {
        removals.push([fn.start, fn.end]);
        continue;
      }
      // (b) Duplicate declaration inside the same container.
      if (seen.has(sig)) {
        removals.push([fn.start, fn.end]);
        continue;
      }
      seen.add(sig);
    }
  }
  if (removals.length) {
    code = removeRanges(code, removals, "conflicting/duplicate function");
    notes.push(
      `removed ${removals.length} conflicting/duplicate function definition(s) that would mask the target's own logic`,
    );
  }

  return { code, notes };
}

/** Signatures compare on normalized types: `transfer(address,uint256)`. */
export function normalizeSignature(signature: string): string {
  const m = signature.match(/^\s*([A-Za-z_]\w*)\s*\(([^)]*)\)/);
  if (!m) return signature.trim().toLowerCase();
  return `${m[1]}(${normalizeParams(m[2])})`.toLowerCase();
}

/**
 * Build the target's function signatures from parsed inventory entries
 * (`name: "Vault.withdraw"`, `params: "uint256 amount, address to"`).
 */
export function functionSignaturesFromInventory(
  functions: { name: string; params: string }[],
): string[] {
  const sigs = new Set<string>();
  for (const fn of functions) {
    const bare = fn.name.includes(".") ? fn.name.slice(fn.name.lastIndexOf(".") + 1) : fn.name;
    if (!bare || bare === "constructor" || bare === "fallback" || bare === "receive") continue;
    sigs.add(`${bare}(${normalizeParams(fn.params ?? "")})`);
  }
  return [...sigs];
}
