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
  assert.equal(ANALYZER_BASELINE, "2026-10-24.1");
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
