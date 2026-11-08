import assert from "node:assert/strict";
import test from "node:test";

import {
  ANALYZER_BASELINE,
  analyzerFingerprint,
  analyzerStamp,
  baselineOf,
  compareBaselines,
  isBaselineOlder,
  isStaleVersion,
} from "./analyzer-version.ts";
import { SMARTBUGS_BY_DETECTOR } from "./smartbugs.ts";

test("the stamp is stable: same code, same stamp", () => {
  assert.equal(analyzerStamp(), analyzerStamp());
  assert.equal(analyzerFingerprint(), analyzerFingerprint());
});

test("the stamp carries the baseline and a hex fingerprint", () => {
  const stamp = analyzerStamp();
  assert.ok(stamp.startsWith(`${ANALYZER_BASELINE}+`), stamp);
  assert.equal(stamp.split("+")[1], analyzerFingerprint());
  assert.match(analyzerFingerprint(), /^[0-9a-f]{16}$/);
});

test("the fingerprint has real material behind it", () => {
  // The fingerprint is only a staleness signal if the detector registry it is
  // computed from is actually populated.
  assert.ok(
    Object.keys(SMARTBUGS_BY_DETECTOR).length >= 20,
    "the detector registry must be populated for the fingerprint to mean anything",
  );
});

test("a missing stamp is stale — that is what refreshes the archive", () => {
  // Every row written before migration 0014 has no stamp. Treating those as
  // stale is what makes the first run after a pipeline change re-analyze the
  // archive instead of skipping it.
  assert.equal(isStaleVersion(null), true);
  assert.equal(isStaleVersion(undefined), true);
  assert.equal(isStaleVersion(""), true);
});

test("the pre-ResNet stamp classifies stale today (the resnet bump landed)", () => {
  // The stamp as computed at the pre-ResNet head (d02615d, the PR #27
  // merge): baseline "2026-10-23.1" plus the fingerprint over that
  // tree's detector categories (token-drain = unchecked_low_level_calls,
  // shadowing = access_control, msg-value-loop = denial_of_service) and
  // its scoring constants, which had no MAX_RESNET_BONUS term. Every
  // archive row carrying this stamp predates ResNet screening and the
  // ML score term — if it ever classified as current again, the
  // pipeline would skip entries that were never screened.
  const PRE_RESNET_STAMP = "2026-10-23.1+26069e703d4873b4";
  assert.equal(isStaleVersion(PRE_RESNET_STAMP), true);
  assert.notEqual(analyzerStamp(), PRE_RESNET_STAMP);
  // Both mechanisms moved in the resnet batch (e0951cf5): the baseline
  // was hand-bumped AND the fingerprint gained MAX_RESNET_BONUS plus
  // three category changes. A stamp matching today on only one of the
  // two halves is still stale.
  // The pin below tracks the CURRENT baseline: it moved again to
  // 2026-10-25.1 in c276b75 (full-bytecode windows + prompt-evidence
  // fixes) — this pin was written against 2026-10-24.1 in the
  // skip-audit batch (82652287) after that bump had already landed,
  // which left this test red on main until it was re-pinned here.
  // It moved again to 2026-10-25.2 with the initializer gate
  // (Fix 37): unprotected-initializer provenance + the critical cap.
  // And to 2026-10-25.3 with the gate generalization (Fix 38):
  // delegatecall / reentrancy / selfdestruct provenance + guard
  // credit — the sweep #2 treatment.
  // And to 2026-10-25.4 with the bytecode-family fix (Fix 39):
  // instruction-proven presence (structural CBOR strip + trailing-
  // constant data exclusion) and operand-resolved DELEGATECALL /
  // CALLCODE severities — the presence-proof treatment.
  // And to 2026-10-27.1 with the detection upgrade from the measured
  // engagement: learned guard names (P7), the Team Just mixer and
  // derived-value entropy (R1/R2), the Blockscout second registry and
  // verified-name label check (C1-C3), and the reachability tag.
  // And to 2026-10-27.2 with the 2026 incident classes: six detectors
  // derived from published post-mortems, each with a modelled harness.
  // And to 2026-10-27.3 with the games work: gate kinds + preconditions
  // (D1), settlement optionality (D2) and registry-dispatched logic (D3).
  // And to 2026-10-27.4 with the six-year incident sweep (2021-2026):
  // dispatch, bridge auth, governance weight, ecrecover zero, oracle staleness.
  // And to 2026-10-27.5 with the detection-quality pass: families,
  // evidence-derived confidence, economic-claim markers, triage order.
  // And to 2026-10-27.6 with the LLM output contract: coerced text,
  // bounded prose, an honest missing-summary line, a code gate.
  // And to 2026-10-27.7 with the four measured weaknesses: pre-0.5 call
  // syntax, presence-note noise, pre-0.8 arithmetic, front-running.
  // And to 2026-10-27.8 with the four deferred classes.
  // And to 2026-10-27.9 with the 2026-era corpus and the two bugs it found.
  // And to 2026-10-27.10 with the recall-first loosening.
  // And to 2026-10-27.11 with the edge-coverage pass (117 -> 131 of 143).
  // And to 2026-10-30.12 with the seven semantic fixes — none of which changed the
  // detector NAME list, which is why the fingerprint stayed put and `refresh: "stale"`
  // kept skipping 88 phantom criticals. See the changelog entry in analyzer-version.ts.
  // And to 2026-11-01.18 with the bridge-message-auth escapes: dynamic-bytes
  // messages only, contract-scoped peer vocabulary, the bound-payee
  // self-service shape, and bridge context for the zero-root half.
  // And to 2026-11-01.19 with the live gates (value exposure + live-state
  // annotations on every fetcher path) and scoreboard demotions.
  // .19 was claimed twice in parallel (live gates in 7dd0223b,
  // reserve-then-rollback reentrancy in 2b86fdbf); .20 supersedes both
  // flavors and restores the baseline-ordering helpers the second push
  // overwrote, plus the scopeSourcifyFiles extraction for the frozen
  // bundle regression corpus.
  // And to 2026-11-06.24 with the ledger-driven calibration batch
  // (Fixes 39-44): the pseudo-constructor detector (SWC-118), the
  // tx-origin != EOA-gate strip + info demotion, the read-only-
  // reentrancy value-decision demotion, the delegatecall
  // fixed-target/fixed-calldata demotion, the unchecked-call notch
  // down, and the erc20-unchecked write-after-call confidence raise.
  // (.21-.23 were bumped without pin entries in this list; the .24
  // bump also re-pins the source digest below, which had drifted
  // stale on main through the 2026-11-02..06 detector commits.)
  // And to 2026-11-06.25 with the SWC coverage batch, first half
  // (Fixes 45-51): old-compiler re-stamped SWC-102, plus new
  // detectors for SWC-108, 109, 111, 113, 128 and 131.
  // And to 2026-11-06.26 with the second half (Fixes 52-58):
  // SWC-110, 123, 125, 126, 127, 129 and 135 — full registry
  // coverage, 37/37.
  assert.equal(ANALYZER_BASELINE, "2026-11-06.26");
  assert.equal(isStaleVersion(`2026-10-23.1+${analyzerFingerprint()}`), true);
  assert.equal(isStaleVersion(`${ANALYZER_BASELINE}+26069e703d4873b4`), true);
});

test("the current stamp is current; anything else is stale", () => {
  assert.equal(isStaleVersion(analyzerStamp()), false);
  assert.equal(isStaleVersion("2026-01-01.1+deadbeefdeadbeef"), true);
  assert.equal(isStaleVersion(`${ANALYZER_BASELINE}+0000000000000000`), true);
  // Same baseline, older fingerprint: a detector or weight changed.
  assert.equal(isStaleVersion(`${ANALYZER_BASELINE}+${"0".repeat(16)}`), true);
});

/**
 * The canary that would have caught 2026-10-30.
 *
 * The fingerprint hashes detector NAMES, categories and scoring constants — never the
 * rule bodies. So a day of semantic fixes moved nothing, `isStampOutOfDate` judged 88
 * phantom criticals current, and `refresh: "stale"` skipped them forever.
 *
 * This test hashes the detector sources. If you change a rule, it fails and tells you to
 * bump ANALYZER_BASELINE — which is the only thing that makes the archive refresh.
 */
test("changing a detector's logic must bump ANALYZER_BASELINE", async () => {
  const { createHash } = await import("node:crypto");
  const { readFileSync } = await import("node:fs");
  // address-fetcher.ts decides WHAT gets analysed (Sourcify scoping, dedupe, bytecode
  // fallback), which is as semantic as a rule change: scoping the bundle to the verified
  // contract's import closure removed 29 criticals without touching a single detector.
  const files = [
    "src/lib/audit/detect.ts",
    "src/lib/audit/bytecode.ts",
    "src/lib/audit/smartbugs.ts",
    "src/lib/audit/address-fetcher.ts",
  ];
  const h = createHash("sha256");
  for (const f of files) h.update(readFileSync(f));
  const digest = h.digest("hex").slice(0, 12);

  // Update this constant ONLY together with ANALYZER_BASELINE. Both move, or neither.
  const DETECTOR_SOURCE_DIGEST = "fc67873c7e90";

  // No placeholder branch: the digest is pinned, so a comparison against a sentinel is
  // dead code and TS rightly calls it unintentional. When the sources change, the
  // assertion below fails and names both values — that is the whole mechanism.
  assert.equal(
    digest,
    DETECTOR_SOURCE_DIGEST,
    "detect.ts/bytecode.ts/smartbugs.ts changed: bump ANALYZER_BASELINE and update " +
      "DETECTOR_SOURCE_DIGEST together, or the archive will keep serving stale findings",
  );
});

test("baselineOf strips the fingerprint and tolerates bare baselines", () => {
  assert.equal(baselineOf("2026-11-01.18+cf54f75a7f37abcd"), "2026-11-01.18");
  assert.equal(baselineOf("2026-11-01.18"), "2026-11-01.18");
  assert.equal(baselineOf(null), null);
  assert.equal(baselineOf(""), null);
});

test("compareBaselines orders by date, then numerically by counter", () => {
  assert.equal(compareBaselines("2026-11-01.18", "2026-11-01.18"), 0);
  assert.equal(compareBaselines("2026-11-01.9", "2026-11-01.10"), -1);
  assert.equal(compareBaselines("2026-11-01.10", "2026-11-01.9"), 1);
  assert.equal(compareBaselines("2026-10-31.16", "2026-11-01.1"), -1);
  // Stamps compare by their baseline part.
  assert.equal(compareBaselines("2026-11-01.16+aaaa", "2026-11-01.18+bbbb"), -1);
  // Unrecognizable input cannot be judged — never "older".
  assert.equal(compareBaselines("garbage", "2026-11-01.18"), null);
  assert.equal(compareBaselines(null, "2026-11-01.18"), null);
  assert.equal(isBaselineOlder("2026-11-01.16", "2026-11-01.18"), true);
  assert.equal(isBaselineOlder("2026-11-01.18", "2026-11-01.16"), false);
  assert.equal(isBaselineOlder("garbage", "2026-11-01.18"), false);
});
