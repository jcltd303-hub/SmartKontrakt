// src/lib/audit/detector-scoreboard.ts
//
// Per-detector verdict scoreboard + automatic demotion. The archive's
// auditor dispositions are a per-detector track record: when a class
// runs ≥90% false-positive over ≥20 dispositioned findings, new
// findings from it are demoted at analysis time — critical caps at
// high, high confidence drops to medium — with the scoreboard line
// written into confidenceBasis so the demotion is never silent.
// bridge-message-auth ran 10-for-10 FP across two vetted pulls while
// still paging criticals; this is the loop that lets a class demote
// itself out of the critical tier on evidence instead of waiting for
// the next hand-vet.
//
// The pure half lives here (decision + report mutation); the SQL
// aggregation lives in detector-scoreboard.server.ts. Dispositions
// remain the auditor's word — the scoreboard only aggregates verdicts
// humans already reached; it originates none.
import type { Report } from "./types.ts";
import { riskScore } from "./risk.ts";

export type DetectorStats = {
  detector: string;
  confirmed: number;
  falsePositive: number;
  needsMoreInfo: number;
  /** Findings carrying any auditor disposition. */
  dispositioned: number;
  /** falsePositive / dispositioned, 0 when nothing is dispositioned. */
  fpRate: number;
};

/** A class must earn demotion: enough verdicts, overwhelmingly FP. */
export const DEMOTION_MIN_DISPOSITIONED = 20;
export const DEMOTION_FP_RATE = 0.9;

export function isDemotionFlagged(stats: DetectorStats): boolean {
  return stats.dispositioned >= DEMOTION_MIN_DISPOSITIONED && stats.fpRate >= DEMOTION_FP_RATE;
}

/**
 * Demote one report's findings for every flagged detector in `stats`.
 * Idempotent: a finding already carrying the demotion note is left
 * alone (the persist seam and the fetcher seam can both run over the
 * same report). Returns how many findings were demoted.
 */
export function applyScoreboardDemotions(
  report: Report,
  stats: ReadonlyMap<string, DetectorStats>,
): number {
  if (stats.size === 0) return 0;
  let demoted = 0;
  for (const f of report.findings) {
    const s = stats.get(f.detector);
    if (!s || !isDemotionFlagged(s)) continue;
    if (f.confidenceBasis?.includes("scoreboard demotion")) continue;
    if (f.severity === "critical") f.severity = "high";
    if (f.confidence === "high") f.confidence = "medium";
    const note =
      `scoreboard demotion: ${f.detector} is ${Math.round(s.fpRate * 100)}% false-positive ` +
      `over ${s.dispositioned} dispositioned findings`;
    f.confidenceBasis = f.confidenceBasis ? `${f.confidenceBasis} · ${note}` : note;
    demoted++;
  }
  if (demoted > 0) report.riskScore = riskScore(report.findings, report.resnet);
  return demoted;
}
