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
