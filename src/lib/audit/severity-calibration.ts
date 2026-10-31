import type { Finding } from "./types.ts";
import { stripCommentsAndStringsKeepLines } from "./strip-source.ts";

/**
 * Severity calibration — a "critical" must be earned, not assumed.
 *
 * The detectors are pattern matchers: they flag shapes that *look* dangerous
 * (an admin-named function with no auth check the parser could see, an ether
 * send with no balance debit it could see, a call-then-write). Before this
 * layer, several of those shapes were reported as critical on medium
 * confidence — i.e. the detector itself was not sure — and on
 * access-controlled functions an external attacker cannot even reach. That
 * is how an ordinary contract with a few admin functions and a withdraw
 * pattern came back as "4 criticals, risk 100" and stopped being believable.
 *
 * Two gates, both transparent: a downgraded finding keeps a note in its
 * summary saying why, so the scrutiny is visible instead of silent.
 *
 * 1. Confidence gate (applied in engine.ts to every finding): a critical
 *    requires high confidence. Medium/low confidence means exploitability is
 *    not confirmed — e.g. an inherited modifier the parser could not see, or
 *    a recipient/amount it could not prove attacker-controlled — so the
 *    finding is a lead, capped at high.
 *
 * 2. Access-control gate (applied in detect.ts where the detector knows
 *    whether the function is access-controlled): a finding on a function an
 *    external attacker cannot call is not a critical exploit. Only the
 *    authorized caller can trigger it, so it is capped at high.
 */
export const CALIBRATION_NOTE_CONFIDENCE =
  "\n\n[Calibrated: critical → high — confidence is not high, so exploitability is not confirmed. Treat as a lead to verify, not a confirmed exploit.]";

export const CALIBRATION_NOTE_AUTHED =
  "\n\n[Calibrated: critical → high — the function is access-controlled, so an external attacker cannot trigger this path directly. Review whether the authorized caller could be tricked or the check bypassed.]";

/** Gate 1: medium/low confidence can never be critical. */
export function calibrateFindings(findings: Finding[]): Finding[] {
  return findings.map((f) => {
    if (f.severity !== "critical") return f;
    if (f.confidence === "high") return f;
    return {
      ...f,
      severity: "high",
      summary: f.summary + CALIBRATION_NOTE_CONFIDENCE,
    };
  });
}

/**
 * Gate 3 note (Fix 37, initializer gate): an unprotected-initializer
 * pattern match is capped at high until LIVE evidence confirms the
 * deployed contract is actually uninitialized. The 2026-10-25 fork
 * proof executed the re-initialization call against all 15 stored
 * criticals of this type (initializer-proof/RESULTS.md) and every one
 * failed: already-initialized guards, access control, functions that
 * do not exist on the deployed contract, and per-pool initializers
 * that succeed by design. Source shape cannot separate those from a
 * genuinely uninitialized contract, so critical is restored only by
 * the live-state gate in initializer-gate.ts (address path), which
 * also marks the finding corroborated. Every other path — pasted
 * source included — keeps this cap and this note.
 */
export const INITIALIZER_GATE_NOTE_UNCONFIRMED =
  "\n\n[Initializer gate: critical requires live evidence — an initialized-state read showing uninitialized, or a simulated initializer call from a fresh address that succeeds and moves privileged state. Source pattern alone caps this at high: live initialized state not confirmed. Address audits run the live probe automatically.]";

/**
 * Gate 4 notes (Fix 38 — the gate generalized to delegatecall,
 * reentrancy and selfdestruct after fork-proof sweep #2, 2026-10-25:
 * 37/37 stored criticals in those classes were false positives —
 * guards the detector did not credit, internal helpers flagged as
 * entry points, failure-rollback writes read as CEI violations, and
 * payout mechanics that cannot carry a reentry). The Fix 38 gates in
 * detect.ts credit provenance (a flag must be reachable through a
 * public entry, with the claimed control TRUE of that chain) and
 * guards (modifiers — including custom ones — mutexes, fixed-caller
 * gates). When a guard is only PROBABLE — a modifier whose body the
 * detector cannot resolve, or one it cannot prove is or is not a
 * caller check — the finding caps at high with the note below: never
 * silently muted, never credited as proven either.
 */
export function unverifiedModifierNote(modifierNames: string[]): string {
  const names = modifierNames.length ? modifierNames.join(", ") : "an unresolvable modifier";
  return `\n\n[Fix 38 guard gate: critical → high — the flagged path carries modifier ${names}, which could not be resolved to a body provably free of a caller check. An unverified modifier is treated as a possible access control: the claim that an arbitrary caller can trigger this is not earned until the modifier is read.]`;
}

export const DELEGATECALL_INITIALIZER_ENTRY_NOTE =
  "\n\n[Fix 38 provenance gate: critical → high — the only public path to this delegatecall is the contract's initializer entry point, so whether it can still be reached is exactly the live initialized-state question the initializer gate answers on the address path (Fix 37). Source alone does not earn the critical here.]";

export const DELEGATECALL_FIXED_TARGET_NOTE =
  "\n\n[Fix 38 provenance gate: reclassified — the delegatecall target is stored state at every public entry that reaches this site; the caller supplies calldata, never the code address. The residual risk is governance trust in whoever can change the stored address. On the 2026-10-25 fork sweep this exact shape (a public entry delegating to a stored implementation) never confirmed as exploitable.]";

/** Gate 4 cap: critical → high with an explicit gate note appended. */
export function withGateCap(finding: Finding, note: string): Finding {
  if (finding.severity !== "critical") return finding;
  return { ...finding, severity: "high", summary: finding.summary + note };
}

/** Gate 2: a finding on an access-controlled function is capped at high. */
export function withAccessControlCap(finding: Finding, authed: boolean): Finding {
  if (!authed) return finding;
  if (finding.severity !== "critical") return finding;
  return {
    ...finding,
    severity: "high",
    summary: finding.summary + CALIBRATION_NOTE_AUTHED,
  };
}

/**
 * Gate 4: a proxy shell's own mechanism is not a finding.
 *
 * Measured 2026-10-28 on 0xDD9BC35aE942eF0cFa76930954a156B3fF30a4E1 — a verified,
 * 27-line OpenZeppelin ERC1967Proxy whose entire source is a constructor and an
 * internal `_implementation()` view. The archive recorded 29 criticals against it:
 * 17 `delegatecall`, 6 `arbitrary-dispatch-call`, 5 `selfdestruct`, 1
 * `unprotected-admin`. Five of those are impossible — that contract contains no
 * selfdestruct at all — so the row was stale, but the 17 delegatecalls are not: a
 * proxy delegates every call by design, and its upgrade guard lives in the
 * implementation, at a different address, which no single-contract scan can see.
 *
 * Across a 24-contract sample, five such rows carried 145 of 171 criticals. A rule
 * that fires on the mechanism makes the severity column useless.
 *
 * So: when the source is a proxy shell, findings that describe the shell's own
 * delegation are informational, and findings about the upgrade guard are capped at
 * medium until the implementation is examined. The note says which, so the
 * downgrade is visible rather than silent. The implementation is queued as its own
 * scan by the worker, which is where those guards are actually checkable.
 *
 * Deliberately conservative: a `delegatecall` in ordinary business logic, with no
 * fallback and no `_implementation` accessor, is left alone.
 */

/** Detectors that describe a proxy's delegation rather than a defect. */
const PROXY_MECHANISM_DETECTORS = new Set(["delegatecall", "arbitrary-dispatch-call"]);

/** Detectors whose guard normally lives in the implementation, not the shell. */
const PROXY_GUARD_DETECTORS = new Set(["unprotected-admin", "unprotected-upgrade"]);

export const CALIBRATION_NOTE_PROXY_MECHANISM =
  "\n\n[Calibrated: critical → info — this is the proxy's own delegation mechanism. A proxy forwards every call by design; the finding describes the pattern, not a defect in it.]";

export const CALIBRATION_NOTE_PROXY_GUARD =
  "\n\n[Calibrated: critical → medium — this is a proxy shell, so the upgrade/admin guard normally lives in the implementation contract at a different address, which a single-contract scan cannot see. Verify against the implementation, which is scanned separately.]";

/**
 * Is this source a proxy shell?
 *
 * True when it delegates from a fallback (or a `_delegate`/`_fallback` helper) AND
 * exposes an implementation accessor, which together are the proxy pattern rather
 * than ordinary delegatecall use. A shell that also contains `selfdestruct` is not
 * treated as one: that is a different contract with real behaviour.
 */
export function looksLikeProxyShell(source: string): boolean {
  if (!source) return false;
  // Judge the COMMENT- AND STRING-STRIPPED view, for the same reason the selfdestruct
  // detector had to. Measured 2026-10-31: 0x0c0388e4 kept all 29 of its criticals on a
  // fresh 2026-10-30.12 run while its sibling went to 0, because its flattened body
  // mentions `selfdestruct(` in a doc comment. That comment disabled this gate, so the
  // 17 delegatecall and 6 arbitrary-dispatch findings stayed critical. A comment is not
  // behaviour, and it must not be able to switch a gate off.
  const view = stripCommentsAndStringsKeepLines(source);
  if (!/delegatecall/i.test(view)) return false;
  if (/selfdestruct\s*\(/i.test(view)) return false;

  const hasFallbackDelegation =
    /function\s+(fallback|receive|_fallback|_delegate)\s*\(/i.test(view) ||
    /\bfallback\s*\(\s*\)\s*external/i.test(view) ||
    /\breceive\s*\(\s*\)\s*external/i.test(view);
  const hasImplementationAccessor =
    /function\s+(_implementation|_getImplementation|getImplementation|implementation|_logic)\s*\(/i.test(view) ||
    /360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc/i.test(source); // EIP-1967 slot

  return hasFallbackDelegation && hasImplementationAccessor;
}

/** Gate 4: apply the proxy-shell calibration. */
export function calibrateProxyShell(findings: Finding[], source: string): Finding[] {
  if (!looksLikeProxyShell(source)) return findings;
  return findings.map((f) => {
    if (PROXY_MECHANISM_DETECTORS.has(f.detector)) {
      return { ...f, severity: "info", summary: f.summary + CALIBRATION_NOTE_PROXY_MECHANISM };
    }
    if (PROXY_GUARD_DETECTORS.has(f.detector) && f.severity === "critical") {
      return { ...f, severity: "medium", summary: f.summary + CALIBRATION_NOTE_PROXY_GUARD };
    }
    return f;
  });
}
