/**
 * What produced a saved record — so "already saved" can mean "already saved by
 * the CURRENT analyzer" rather than "already saved by anything".
 *
 * The pipeline's skip/resume treats a saved (chain, address) as done. That is
 * correct only while the analyzer is unchanged: after the scoring redo, the
 * balance guard, the value-at-risk pass, ABI gathering, SmartPoC, or the
 * SmartBugs alignment, every earlier row is a record of *older* behaviour —
 * its findings, risk score and value are stale, and skipping it preserves the
 * staleness. Storing a stamp on each row makes resume version-aware: a run
 * refreshes exactly what is out of date and still skips the rest.
 *
 * Two mechanisms, deliberately:
 *
 *  - The FINGERPRINT is computed, not written by hand, from the things that
 *    define the analyzer's output: the detector set and its category mapping
 *    (which `npm run check:detectors` already forces to stay complete) and the
 *    scoring model's constants. Add a detector or change a weight and the
 *    fingerprint moves on its own — it cannot silently rot.
 *
 *  - The BASELINE is a hand-bumped string for changes the fingerprint cannot
 *    see: a detector's *logic* being corrected, a prompt or template changing,
 *    a new pipeline stage. Bump it when the same input would now produce a
 *    different record.
 *
 * Its own module with no server imports, so the worker, the browser and the
 * tests all agree on the same stamp.
 */
import { sha3_256 } from "js-sha3";

import { SMARTBUGS_BY_DETECTOR } from "./smartbugs.ts";
import {
  CONFIRMED_EXPLOIT_BONUS,
  MAX_COMPOUND_BONUS,
  MAX_VOLUME_BONUS,
  SEVERITY_FLOOR,
} from "./risk.ts";

/**
 * Bump when the same input would now produce a different record but the
 * detector set and scoring constants are unchanged.
 *
 * 2026-10-21.1 — scoring model redo (dominance-first), balance guard,
 *                value-at-risk, ABI gathering, SmartPoC, SmartBugs alignment.
 * 2026-10-23.1 — FP-pattern batch from the live-archive poll (Fixes
 *                32-36): solc-metadata + opcode-presence findings
 *                demoted (bytecode DELEGATECALL/SELFDESTRUCT/CALLCODE
 *                presence and compiler-version notes are low, never
 *                critical/high), unparsed regex hits are info,
 *                read-only reentrancy with a getter-only consumer is
 *                low, and the standard proxy upgrade/initialize
 *                surface no longer raises criticals. Same inputs now
 *                produce different records, so the archive refreshes.
 */
export const ANALYZER_BASELINE = "2026-10-23.1";

/** A stable digest of the detector set + scoring constants. */
export function analyzerFingerprint(): string {
  const detectors = Object.keys(SMARTBUGS_BY_DETECTOR).sort();
  const material = JSON.stringify({
    detectors,
    categories: detectors.map((d) => SMARTBUGS_BY_DETECTOR[d]),
    scoring: { SEVERITY_FLOOR, MAX_VOLUME_BONUS, CONFIRMED_EXPLOIT_BONUS, MAX_COMPOUND_BONUS },
  });
  return sha3_256(material).slice(0, 16);
}

/** The stamp written on every saved record: baseline + fingerprint. */
export function analyzerStamp(): string {
  return `${ANALYZER_BASELINE}+${analyzerFingerprint()}`;
}

/**
 * Is a saved record's stamp out of date? A missing stamp (every row written
 * before this column existed) is stale by definition — that is what makes the
 * first run after this change refresh the whole archive instead of skipping it.
 */
export function isStaleVersion(saved?: string | null): boolean {
  return !saved || saved !== analyzerStamp();
}
