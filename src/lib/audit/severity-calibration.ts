import type { Finding } from "./types.ts";

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
