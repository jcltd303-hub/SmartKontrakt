import assert from "node:assert/strict";
import test from "node:test";

import {
  ANALYZER_BASELINE,
  analyzerFingerprint,
  analyzerStamp,
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
  assert.equal(ANALYZER_BASELINE, "2026-10-27.4");
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
