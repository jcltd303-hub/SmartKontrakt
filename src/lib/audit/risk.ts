/**
 * Risk score — a 0-100 index that reflects the WORST thing present.
 *
 * The previous model was a capped sum (`min(100, Σ weight)`) with
 * `critical: 28`. A single critical therefore scored 28, and a critical plus a
 * high scored 42 — so a contract with a critical vulnerability read as "medium"
 * and the number stopped being a triage signal. Worse, a lone `high` scored 14
 * and a lone `medium` scored 6, both landing in the "low" band.
 *
 * This model is dominance-first, which is how a security triage actually reads:
 *
 *   score = floor(worst severity)          ← one critical can never read as medium
 *         + bounded pressure for the rest   ← 10 mediums never outrank a critical
 *         + a bonus for PoC-confirmed exploits
 *
 * Bands line up with the ones the UI already filters on (75 / 50 / 25), so the
 * number, the colour and the filter agree.
 *
 * Value at risk is deliberately NOT folded in: it is an orthogonal axis, kept
 * separate so a critical on a valueless contract still ranks as a critical.
 */
import type { Finding, Severity } from "./types.ts";

export type RiskBand = "critical" | "high" | "medium" | "low" | "none";

/** Floor each severity guarantees. One critical alone lands in the critical band. */
export const SEVERITY_FLOOR: Record<Severity, number> = {
  critical: 78,
  high: 55,
  medium: 30,
  low: 12,
  info: 0,
};

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Maximum the "more findings" term may add, so volume can never dominate severity. */
export const MAX_VOLUME_BONUS = 12;
/** Points added when at least one finding has a reproduced (fork-passed) exploit. */
export const CONFIRMED_EXPLOIT_BONUS = 10;
/** Maximum extra points for further confirmed exploits. */
export const MAX_COMPOUND_BONUS = 6;

/** The most severe finding, by severity rank. */
export function worstFinding(findings: Finding[]): Finding | null {
  if (findings.length === 0) return null;
  return findings.reduce((worst, f) => (RANK[f.severity] < RANK[worst.severity] ? f : worst));
}

/**
 * 0-100 risk index. Dominance-first: the worst finding sets the floor, the rest
 * add diminishing pressure, and reproduced exploits add proof weight.
 */
export function riskScore(findings: Finding[]): number {
  if (findings.length === 0) return 0;

  const worst = worstFinding(findings);
  if (!worst) return 0;

  let score = SEVERITY_FLOOR[worst.severity];

  // Additional findings add pressure, but bounded — so ten mediums cannot
  // overtake a single critical.
  const extra = findings.length - 1;
  if (extra > 0) score += Math.min(MAX_VOLUME_BONUS, extra * 2);

  // A fork-PoC that passed is proof, not a lead: it deserves to rank at the top.
  const confirmed = findings.filter((f) => f.pocStatus === "passed").length;
  if (confirmed > 0) {
    score += CONFIRMED_EXPLOIT_BONUS;
    if (confirmed > 1) score += Math.min(MAX_COMPOUND_BONUS, (confirmed - 1) * 3);
  }

  return Math.max(0, Math.min(100, Math.round(score)));
}

/** The band a score falls in — the same thresholds the UI filters on. */
export function riskBand(score: number): RiskBand {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  if (score >= 1) return "low";
  return "none";
}
