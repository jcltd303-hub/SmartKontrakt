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
  MAX_RESNET_BONUS,
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
 * 2026-10-24.1 — ResNet1D screening runs inside the audit for every
 *                entry (new pipeline stage): the record gains
 *                resnet_json (migration 0018) and risk scores gain
 *                the bounded ML term (MAX_RESNET_BONUS, also hashed
 *                into the fingerprint below). Same inputs now produce
 *                different records, so the archive refreshes.
 * 2026-10-25.2 — Initializer gate (Fix 37): unprotected-initializer
 *                candidates must be externally reachable functions of
 *                a contract (internal/private and library/interface
 *                members no longer flag), the source pattern alone
 *                caps at high, and critical + corroborated require
 *                positive live evidence from the address-path probe
 *                (initializer-gate.ts) — the fork proof showed all
 *                15 stored criticals of this type were false
 *                positives. Same inputs now produce different
 *                records, so the archive refreshes.
 * 2026-10-25.3 — Gate generalization (Fix 38): the Fix 37 discipline
 *                extended to delegatecall, reentrancy and
 *                selfdestruct after fork-proof sweep #2 showed 37/37
 *                stored criticals in those classes were false
 *                positives. Delegatecall sites are judged through
 *                their public entry chain (proven-unreachable sites
 *                drop, fixed/stored targets reclassify low, guards
 *                and unverifiable modifiers on the entries cap);
 *                reentrancy reads the mechanics (failure-rollback
 *                writes are CEI-clean, low gas caps close the window,
 *                hand-rolled mutexes count as guards, fixed-router
 *                payout legs are low) and attributes helper findings
 *                to their public entries; selfdestruct credits deep
 *                custom-modifier checks (onlymanyowners) and
 *                requires external reachability. Source-only: no
 *                finding is newly corroborated. Same inputs now
 *                produce different records, so the archive refreshes.
 * 2026-10-25.4 — Bytecode-family fix (Fix 39): opcode presence is now
 *                instruction-proven — the auxdata tail is stripped by
 *                structural CBOR parsing (iterated, so embedded
 *                contracts' tails go too) and the solc trailing-
 *                constant word is excluded as data — after the
 *                presence proof showed 21/72 stored bytecode-callcode
 *                highs had no CALLCODE instruction at all. DELEGATECALL
 *                and CALLCODE are separate findings whose severity
 *                comes from operand resolution: calldata-derived
 *                target high, fixed constant / proxy-slot target
 *                informational, unresolvable target stays low with
 *                the gap named (delegatecall sample 30/30 and
 *                callcode 72/72 were FP-as-high). SELFDESTRUCT and
 *                metadata severities are NOT recalibrated — presence
 *                correctness only. Same inputs now produce different
 *                records, so the archive refreshes.
 * 2026-10-27.1 — Detection upgrade from the measured engagement (480
 *                hits → 1 real issue, 47% FP rate). Precision: the
 *                learned guard-name list (P7) credits ownerOnly /
 *                hasMintPermission / isPlayer / treasuryOnly /
 *                oraclizeAction as proven access control, while a bare
 *                onlyXxx convention stays a possible guard (cap +
 *                note). Recall: the Team Just five-field block mixer
 *                (R1) and derived-value entropy — a hash of block data
 *                whose OUTPUT is later selected on (R2) — now flag,
 *                with the identifier-only suppression preserved.
 *                Coverage/identity: Blockscout is a second verified-
 *                source registry (C1) and a bytecode-only audit is
 *                labelled analysed, not unreadable (C2), with the
 *                verified name and a label check recorded (C3).
 *                Adjudication: every finding whose function the model
 *                resolves carries a reachability class (Phase 4). Same
 *                inputs now produce different records, so the archive
 *                refreshes.
 * 2026-10-27.2 — 2026 incident classes: six detectors derived from
 *                published post-mortems (hook-callback-auth,
 *                calldata-offset-auth, eoa-only-guard,
 *                public-key-account-trust, unauthenticated-batch-call,
 *                self-attested-auth), each with a modelled Foundry
 *                harness (47-52). New findings on inputs that
 *                previously produced none, so the archive refreshes.
 */
// Full-byte windows, explicit missing evidence and finding-specific prompt fixes.
export const ANALYZER_BASELINE = "2026-10-27.2";

/** A stable digest of the detector set + scoring constants. */
export function analyzerFingerprint(): string {
  const detectors = Object.keys(SMARTBUGS_BY_DETECTOR).sort();
  const material = JSON.stringify({
    detectors,
    categories: detectors.map((d) => SMARTBUGS_BY_DETECTOR[d]),
    scoring: { SEVERITY_FLOOR, MAX_VOLUME_BONUS, CONFIRMED_EXPLOIT_BONUS, MAX_COMPOUND_BONUS, MAX_RESNET_BONUS },
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
