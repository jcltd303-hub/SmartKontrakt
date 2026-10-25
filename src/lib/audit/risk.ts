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
import { severityRank } from "./severity.ts";
import { resnetRiskBonus, type ResnetResult } from "./resnet-result.ts";

/** Re-exported so the analyzer fingerprint hashes this constant too. */
export { MAX_RESNET_BONUS } from "./resnet-result.ts";

export type RiskBand = "critical" | "high" | "medium" | "low" | "none";

/** Floor each severity guarantees. One critical alone lands in the critical band. */
export const SEVERITY_FLOOR: Record<Severity, number> = {
  critical: 78,
  high: 55,
  medium: 30,
  low: 12,
  info: 0,
};

/** Maximum the "more findings" term may add, so volume can never dominate severity. */
export const MAX_VOLUME_BONUS = 12;
/** Points added when at least one finding has a reproduced (fork-passed) exploit. */
export const CONFIRMED_EXPLOIT_BONUS = 10;
/** Maximum extra points for further confirmed exploits. */
export const MAX_COMPOUND_BONUS = 6;

/** The most severe finding, by severity rank. */
export function worstFinding(findings: Finding[]): Finding | null {
  if (findings.length === 0) return null;
  return findings.reduce((worst, f) =>
    severityRank(f.severity) < severityRank(worst.severity) ? f : worst,
  );
}

/**
 * 0-100 risk index. Dominance-first: the worst finding sets the floor, the rest
 * add diminishing pressure, and reproduced exploits add proof weight.
 *
 * The optional ResNet1D result (resnet-result.ts) adds one more bounded
 * pressure term, and nothing else:
 *   - it is consulted ONLY here, and only when static analysis found
 *     something above info — a findings-free report scores 0 and an
 *     info-only report is untouched, no matter what the model flags,
 *     so ResNet alone can never mint risk out of nothing;
 *   - it adds at most MAX_RESNET_BONUS (6) points, capped within the
 *     static score's severity band. ML cannot promote low to medium.
 *   - it never lowers a score and never touches a finding's severity.
 */
export function riskScore(findings: Finding[], resnet?: ResnetResult | null): number {
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

  // ResNet1D screening term — bounded ML pressure, see the header above.
  // The floor guard is the gate: info-severity "findings" are notes, not
  // signal, so a report whose worst finding is info gets no ML term.
  const staticScore = Math.max(0, Math.min(100, Math.round(score)));
  const bandCeiling = staticScore >= 75 ? 100 : staticScore >= 50 ? 74 : staticScore >= 25 ? 49 : 24;
  if (SEVERITY_FLOOR[worst.severity] > 0) score = Math.min(bandCeiling, staticScore + resnetRiskBonus(resnet));

  return Math.max(0, Math.min(100, Math.round(score)));
}

/**
 * The band, in the vocabulary stored in the knowledge base ("none" is not one of
 * the severities the chunk table accepts).
 *
 * Lives here, with `riskBand`, so the chunk tag and the UI filter cannot
 * disagree. They used to: the RAG chunks had their own 60/30 scale while the
 * Records tab filtered on 75/50/25, so a contract scoring 65 was tagged
 * "critical" in the knowledge base and shown as "high" in the list.
 */
export function riskBandForChunk(score: number): Severity {
  const band = riskBand(score);
  return band === "none" ? "info" : band;
}

/** Display label per band, so every surface names the same band the same way. */
export const RISK_LABEL: Record<RiskBand, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  none: "NONE",
};

/** The band a score falls in — the same thresholds the UI filters on. */
export function riskBand(score: number): RiskBand {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  if (score >= 1) return "low";
  return "none";
}
