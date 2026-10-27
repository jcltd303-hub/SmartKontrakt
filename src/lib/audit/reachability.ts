// src/lib/audit/reachability.ts
//
// Phase 4 of the 2026-10-27 detection upgrade: automatic reachability
// adjudication.
//
// The engagement that produced this module measured the problem precisely:
// 480 detector hits yielded ONE genuine issue. Every false positive in that
// set was a shape that existed but was gated, internal, self-addressed, or
// unreachable — so the decisive question is never "does this pattern exist"
// but "who can reach it, and what can they take". This module answers that
// question mechanically, in the plan's vocabulary:
//
//   REACHABLE   an unprivileged caller can invoke it and the value flow is
//               not bounded to their own accounting — this is a finding.
//   GATED       a privileged caller only (owner/role/custom modifier or a
//               msg.sender check in the body). A trust note, not a theft.
//   INTERNAL    not externally callable, or a constructor, or an internal
//               helper with no public entry that reaches it.
//   BOUNDED     externally callable and moves value, but the recipient is
//               the caller (or a fixed address) and the amount is bounded by
//               caller-owned accounting — a refund/withdrawal, not a drain.
//   NEEDS_READ  a guard is plausibly present but could not be resolved
//               (an imported modifier with an unknown name). Never silently
//               promoted to REACHABLE: uncertainty costs a human read.
//
// Everything here is a pure function of its inputs — no database, no
// network, no model import beyond types — so the whole classification matrix
// is unit-testable (reachability.test.ts). It does not change any detector's
// verdict by itself; detectSource attaches the class to each finding so the
// workbench and the adjudication chain can order the read queue by it.

import type { FnModel } from "./model.ts";

export type ReachabilityClass = "REACHABLE" | "GATED" | "INTERNAL" | "BOUNDED" | "NEEDS_READ";

export const REACHABILITY_CLASSES: readonly ReachabilityClass[] = [
  "REACHABLE",
  "GATED",
  "INTERNAL",
  "BOUNDED",
  "NEEDS_READ",
] as const;

export type ReachabilityVerdict = {
  class: ReachabilityClass;
  /** One line, shown next to the finding: why this class. */
  reason: string;
  /** The evidence the verdict rests on (modifier names, the guard text). */
  evidence: string[];
};

export type ReachabilityInput = {
  visibility: string;
  mutability?: string;
  isConstructor?: boolean;
  modifiers?: string[];
  /** The function body (or whole declaration) as source text. */
  bodySource: string;
  /** True when the site moves value: an ether send, or a token transfer. */
  movesValue?: boolean;
  /** Recipient expressions of the value moves (msg.sender, to, address(this)…). */
  sendTargets?: string[];
  /** Amount expressions of the value moves. */
  amountExprs?: string[];
  /** The function's parameter names — a recipient equal to one of these is
   *  caller-chosen. */
  paramNames?: string[];
  /** State variables the contract declares, with their immutability. */
  stateVars?: { name: string; constOrImmutable: boolean }[];
  /** State variables this function assigns — a stored recipient it writes is
   *  caller-chosen, one it never writes is fixed. */
  writesStateVars?: string[];
  /** True when the amount is bounded by accounting the caller owns
   *  (mapping[msg.sender], user.amount, balances[_msgSender()]). */
  callerOwnedAccounting?: boolean;
  /** An internal/private function reached by a public entry point. */
  reachableFromPublicEntry?: boolean;
  /** The compilation declares contracts deriving from this one, so an
   *  internal site may be exposed by code this analysis cannot see. */
  hasDerivedContracts?: boolean;
};

/** Modifiers that are provably NOT access control: reentrancy guards and
 *  state gates. Crediting these as auth is the failure mode P7 names —
 *  `onlyActive` is a state gate and authenticates nobody. */
const NON_GATE_MODIFIERS = new Set([
  "nonreentrant",
  "noreentrant",
  "reentrancyguard",
  "lock",
  "mutex",
  "whennotpaused",
  "whenpaused",
  "onlyactive",
  "onlyopen",
  "onlystarted",
  "onlyenabled",
  "onlyrunning",
  "onlyonce",
  "onlyended",
  "onlylive",
  "onlyunlocked",
  "onlyready",
  "onlyvalid",
  "onlywhenactive",
  "onlynotpaused",
  "onlybeforeend",
  "onlyafterstart",
  "onlyduring",
  "wheninitialized",
  "initializer",
  "reinitializer",
]);

/** Learned guard names (P7): custom modifier names seen gating real
 *  contracts in the engagement — `ownerOnly` (Bancor),
 *  `hasMintPermission`, `oraclizeAction`, `isPlayer`, `treasuryOnly`. The
 *  `onlyXxx` / `isXxx` / `hasXxx` conventions cover most of the rest; this
 *  list carries the ones that do not follow a convention. */
const LEARNED_GUARD_MODIFIERS = new Set([
  "checkadmin",
  "restricted",
  "auth",
  "authorized",
  "adminonly",
  "owneronly",
  "treasuryonly",
  "oraclizeaction",
  "isplayer",
  "hasmintpermission",
  "onlykeeper",
  "onlymanager",
  "onlyrelayer",
  "onlycontroller",
  "onlydeployer",
  "onlysigner",
  "onlyteam",
  "onlywhitelisted",
  "whitelisted",
  "governanceonly",
]);

function flat(name: string): string {
  return name.replace(/[_\s]/g, "").toLowerCase();
}

/**
 * A name from the LEARNED list only — the modifiers this engagement saw
 * gating real contracts (`ownerOnly`, `hasMintPermission`, `isPlayer`,
 * `treasuryOnly`, `oraclizeAction`). Deliberately narrower than
 * isGuardModifierName: a name is only PROVEN access control for the
 * detector when someone has actually read one, because crediting a guard
 * as proven suppresses a finding. A modifier that merely follows the
 * `onlyXxx` convention (`onlyBeacon`) is a POSSIBLE guard — it caps the
 * finding at high with a note naming it, exactly as Fix 38 requires, and
 * never silently clears it.
 */
export function isExplicitGuardModifierName(name: string): boolean {
  const key = flat(name.trim());
  if (!key) return false;
  if (NON_GATE_MODIFIERS.has(key)) return false;
  return LEARNED_GUARD_MODIFIERS.has(key);
}

/**
 * Does this modifier name mean "privileged caller only"?
 *
 * `onlyOwner`/`onlyRole`/`onlyAdmin` match by convention; `onlyActive` is a
 * state gate and is explicitly excluded (P7); `isPlayer`/`hasMintPermission`
 * match the is/has convention; the rest come from the learned list.
 */
export function isGuardModifierName(name: string): boolean {
  const raw = name.trim();
  if (!raw) return false;
  const key = flat(raw);
  if (NON_GATE_MODIFIERS.has(key)) return false;
  if (/^only[A-Z]/.test(raw)) return true;
  if (/^(?:is|has)[A-Z]/.test(raw)) return true;
  if (LEARNED_GUARD_MODIFIERS.has(key)) return true;
  // Imported, unreadable and not matching a convention: unknown, not a gate.
  return false;
}

/** A modifier the classifier could not place either way. */
function isUnresolvedModifierName(name: string, knownGuardBodies: Set<string>): boolean {
  const key = flat(name);
  if (!key) return false;
  if (NON_GATE_MODIFIERS.has(key)) return false;
  if (isGuardModifierName(name)) return false;
  // An in-file modifier whose body the caller resolved is not unknown — the
  // caller only leaves a name here when it has no body for it.
  return !knownGuardBodies.has(key);
}

/** Collapse whitespace so a guard split across lines still matches (P6:
 *  `require(\n  msg.sender == owner\n)` in KydyCore). */
function squash(src: string): string {
  return src.replace(/\s+/g, " ").trim();
}

/** A privileged party expression: an identifier or dotted member access
 *  (`owner`, `config.admin`, `_roles.GOVERNOR`). Deliberately NOT an index
 *  expression — `items[id].owner` is a per-asset owner, not a global gate. */
const PRIVILEGED = "[A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*";
const SENDER = "(?:msg\\.sender|_msgSender\\s*\\(\\s*\\))";

/** Reject a captured "privileged" expression that is really a per-asset
 *  owner (`.owner`) or the contract itself — neither gates a caller. */
function isGlobalPrivileged(text: string): boolean {
  const t = text.trim();
  if (!t) return false;
  if (/\[/.test(t)) return false;
  if (/\.owner$/.test(t)) return false;
  if (/^(?:this|address)$/.test(t)) return false;
  return true;
}

/** Body-level sender guards. Each is an equality/deny check on msg.sender
 *  (or the OZ `_msgSender()` alias) against a privileged party. */
const BODY_GUARD_PATTERNS: { re: RegExp; note: string }[] = [
  { re: new RegExp(`require\\s*\\(\\s*${SENDER}\\s*==\\s*(${PRIVILEGED})`), note: "require(msg.sender == <privileged>)" },
  { re: new RegExp(`require\\s*\\(\\s*(${PRIVILEGED})\\s*==\\s*${SENDER}`), note: "require(<privileged> == msg.sender)" },
  { re: new RegExp(`if\\s*\\(\\s*${SENDER}\\s*!=\\s*(${PRIVILEGED})[^)]*\\)\\s*(?:\\{\\s*)?(?:revert|throw|require\\s*\\(\\s*false)`), note: "if (msg.sender != <privileged>) revert" },
  { re: new RegExp(`if\\s*\\(\\s*(${PRIVILEGED})\\s*!=\\s*${SENDER}[^)]*\\)\\s*(?:\\{\\s*)?(?:revert|throw|require\\s*\\(\\s*false)`), note: "if (<privileged> != msg.sender) revert" },
  { re: /\b_checkOwner\s*\(|\b_requireOwner\s*\(|\bonlyOwner\s*\(/, note: "OZ _checkOwner()" },
  { re: /\bhasRole\s*\(\s*[A-Za-z_$][\w$]*\s*,\s*(?:msg\.sender|_msgSender\s*\(\s*\))/, note: "hasRole(role, msg.sender)" },
  { re: new RegExp(`(?:require|if)\\s*\\([^)]*\\b(?:isOwner|isAdmin|isGovernance)\\s*\\(\\s*(?:msg\\.sender|_msgSender\\s*\\(\\s*\\))\\s*\\)`), note: "isOwner(msg.sender) style check" },
];

/** Per-asset ownership (`item.owner == msg.sender`, `ownerOf(id) ==
 *  msg.sender`): the caller owns THAT asset, which bounds the value flow
 *  rather than gating the function. */
const PER_ITEM_GUARD = /[A-Za-z_$][\w$.[\]]*\.owner\s*==\s*(?:msg\.sender|_msgSender\s*\(\s*\))|ownerOf\s*\([^)]*\)\s*==\s*(?:msg\.sender|_msgSender\s*\(\s*\))/;

/** Fixed recipient: a literal address, the contract itself, or a
 *  const/immutable it never assigns. */
function isFixedRecipient(
  target: string,
  input: ReachabilityInput,
): boolean {
  const text = squash(target);
  if (!text) return false;
  if (/^0x[0-9a-fA-F]{40}$/.test(text)) return true;
  const squashed = text.replace(/\s+/g, "");
  if (squashed === "address(this)" || squashed === "payable(address(this))") return true;
  if (/^[A-Za-z_$][\w$]*$/.test(text)) {
    const sv = (input.stateVars ?? []).find((s) => s.name === text);
    if (sv) {
      if (sv.constOrImmutable) return true;
      const written = (input.writesStateVars ?? []).includes(text);
      return !written;
    }
  }
  return false;
}

function isCallerRecipient(target: string): boolean {
  return /(?:msg\.sender|_msgSender\s*\(\s*\))/.test(target);
}

/**
 * Classify one call site. Order matters and is deliberate:
 *
 *   INTERNAL  → nothing else can be true of a site no caller reaches.
 *   GATED     → a privileged path is a trust note whatever the value flow.
 *   NEEDS_READ→ an unresolvable guard is not evidence of reachability.
 *   BOUNDED   → value moves, but only the caller's own, within their bound.
 *   REACHABLE → the remainder: this is the one class that becomes a finding.
 */
export function classifyReachability(input: ReachabilityInput): ReachabilityVerdict {
  const body = squash(input.bodySource ?? "");
  const modifiers = (input.modifiers ?? []).filter(Boolean);
  const evidence: string[] = [];

  // --- INTERNAL -----------------------------------------------------
  const vis = (input.visibility || "default").toLowerCase();
  if (input.isConstructor) {
    return { class: "INTERNAL", reason: "constructor: runs once at deployment, no caller entry", evidence: ["constructor"] };
  }
  if (vis === "internal" || vis === "private") {
    if (input.reachableFromPublicEntry) {
      evidence.push(`reached from a public entry (declared ${vis})`);
    } else if (input.hasDerivedContracts) {
      return {
        class: "NEEDS_READ",
        reason: `declared ${vis} but the compilation declares contracts deriving from this one — exposure uncertain`,
        evidence: [`visibility: ${vis}`, "derived contracts present"],
      };
    } else {
      return { class: "INTERNAL", reason: `declared ${vis} with no public entry reaching it`, evidence: [`visibility: ${vis}`] };
    }
  }

  // --- GATED --------------------------------------------------------
  const guardMods = modifiers.filter(isGuardModifierName);
  if (guardMods.length > 0) {
    evidence.push(`modifier: ${guardMods.join(", ")}`);
    return { class: "GATED", reason: `privileged entry (${guardMods.join(", ")})`, evidence };
  }
  for (const { re, note } of BODY_GUARD_PATTERNS) {
    const hit = body.match(re);
    if (!hit) continue;
    const privileged = hit[1] ?? "";
    if (privileged && !isGlobalPrivileged(privileged)) continue; // per-asset, not a gate
    evidence.push(note);
    return { class: "GATED", reason: `privileged entry (${note})`, evidence };
  }

  // --- NEEDS_READ: an unresolvable modifier -------------------------
  const unresolved = modifiers.filter((m) => isUnresolvedModifierName(m, new Set()));
  if (unresolved.length > 0) {
    return {
      class: "NEEDS_READ",
      reason: `unresolved modifier(s) ${unresolved.join(", ")} — could be a guard the classifier cannot see`,
      evidence: [`modifier: ${unresolved.join(", ")}`],
    };
  }

  const perItem = PER_ITEM_GUARD.test(body);
  if (perItem) evidence.push("per-asset ownership check");

  // --- BOUNDED ------------------------------------------------------
  if (input.movesValue) {
    const targets = (input.sendTargets ?? []).map((t) => t.trim()).filter(Boolean);
    const allCaller = targets.length > 0 && targets.every(isCallerRecipient);
    const allFixed = targets.length > 0 && targets.every((t) => isFixedRecipient(t, input));
    const accounting = input.callerOwnedAccounting === true || perItem;
    if ((allCaller || allFixed) && accounting) {
      evidence.push(allCaller ? "recipient is the caller" : "recipient is fixed");
      evidence.push("amount bounded by caller-owned accounting");
      return {
        class: "BOUNDED",
        reason: "moves the caller's own value within their own accounting — a withdrawal, not a drain",
        evidence,
      };
    }
    if (allFixed) {
      evidence.push("recipient is fixed");
      return {
        class: "BOUNDED",
        reason: "moves value to a fixed recipient the caller cannot redirect",
        evidence,
      };
    }
    evidence.push(targets.length ? `recipient: ${targets.join(", ")}` : "value moves with no resolvable recipient");
  }

  // --- REACHABLE ----------------------------------------------------
  return {
    class: "REACHABLE",
    reason: input.movesValue
      ? "unprivileged caller, value flow not bounded to their own accounting"
      : "unprivileged caller can invoke it directly",
    evidence: evidence.length ? evidence : [`visibility: ${vis}`],
  };
}

/** Only REACHABLE becomes a finding (plan §5: stop reporting counts). */
export function isReportable(verdict: ReachabilityVerdict | ReachabilityClass): boolean {
  return (typeof verdict === "string" ? verdict : verdict.class) === "REACHABLE";
}

/** Short UI label for a class. */
export function reachabilityLabel(cls: ReachabilityClass): string {
  switch (cls) {
    case "REACHABLE":
      return "Reachable";
    case "GATED":
      return "Gated";
    case "INTERNAL":
      return "Internal";
    case "BOUNDED":
      return "Bounded";
    case "NEEDS_READ":
      return "Needs read";
  }
}

/**
 * Convenience adapter: classify an FnModel directly. `movesValue` is
 * inferred from the body — a genuine ether send (transfer/send/call{value}),
 * never a token transfer or a `super.` call (P10), and never from a view or
 * pure function (P9).
 */
export function classifyFunction(
  fn: Pick<FnModel, "name" | "visibility" | "mutability" | "modifiers" | "source" | "isConstructor" | "params">,
  extra: Partial<ReachabilityInput> = {},
): ReachabilityVerdict {
  const body = fn.source ?? "";
  const viewOnly = fn.mutability === "view" || fn.mutability === "pure";
  const sendTargets = extra.sendTargets ?? inferEtherRecipients(body);
  const movesValue = extra.movesValue ?? (!viewOnly && sendTargets.length > 0);
  return classifyReachability({
    visibility: fn.visibility,
    mutability: fn.mutability,
    isConstructor: fn.isConstructor,
    modifiers: fn.modifiers,
    bodySource: body,
    movesValue,
    sendTargets,
    paramNames: (fn.params ?? []).map((p) => p.name).filter(Boolean),
    ...extra,
  });
}

/**
 * Recipients of genuine ether sends: `x.transfer(a)`, `x.send(a)`,
 * `x.call{value: a}(...)` and `payable(x).transfer(a)`. Token transfers
 * (`token.transfer(to, amt)`), `super.transfer(...)` (P10) and SafeMath
 * (`.sub`) are not ether sends and never yield a recipient here.
 */
export function inferEtherRecipients(src: string): string[] {
  const out: string[] = [];
  const body = src ?? "";
  for (const m of body.matchAll(/([A-Za-z_$][\w$.()[\]]*)\s*\.\s*(?:transfer|send)\s*\(/g)) {
    const base = (m[1] ?? "").trim();
    if (!base) continue;
    if (/^super$/.test(base.replace(/^payable\(|\)$/g, ""))) continue; // P10
    // A two-argument transfer(...) is an ERC-20 transfer, not ether.
    const after = body.slice(m.index! + m[0].length);
    const depth = { n: 1 };
    let i = 0;
    let commas = 0;
    while (i < after.length && depth.n > 0) {
      const c = after[i];
      if (c === "(") depth.n += 1;
      else if (c === ")") depth.n -= 1;
      else if (c === "," && depth.n === 1) commas += 1;
      i += 1;
    }
    if (commas >= 1) continue;
    out.push(base);
  }
  for (const m of body.matchAll(/([A-Za-z_$][\w$.()[\]]*)\s*\.\s*call\s*\{\s*value\s*:/g)) {
    const base = (m[1] ?? "").trim();
    if (base) out.push(base);
  }
  return [...new Set(out)];
}
