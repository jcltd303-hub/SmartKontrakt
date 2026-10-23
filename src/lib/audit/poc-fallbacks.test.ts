// src/lib/audit/poc-fallbacks.test.ts
//
// Verdict-integrity pins for the fallback-library selection. The library
// audit (2026-10-23) found two ways selection manufactured verdicts:
// detectors declared not-PoC-able silently inherited SmartBugs-category
// harnesses (rtl-override, a HIGH, was handed the open-drain template),
// and wrong-mechanism templates sat in detector maps (35 flash-loan under
// the oracle/slippage detectors, 37 approval-abuse under erc20-unchecked,
// owner-rug 28 ahead of the dedicated locked-ether harness 29). These
// tests pin the corrected state so a future index edit cannot quietly
// reintroduce any of it.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  POC_FALLBACK_BY_DETECTOR,
  POC_FALLBACK_CATALOG,
  POC_NOT_POCABLE_DETECTORS,
  selectPocFallbacks,
} from "./poc-fallbacks.ts";

const filesOf = (picks: Array<{ file: string }>) => picks.map((p) => p.file);
const pick = (detector: string, severity = "high", max = 3) =>
  filesOf(selectPocFallbacks([{ detector, severity }], max));

describe("not-PoC-able detectors select no harness", () => {
  it("emits exactly the audited no-harness set", () => {
    assert.deepEqual(
      [...POC_NOT_POCABLE_DETECTORS].sort(),
      [
        "bytecode-metadata",
        "bytecode-reentrancy-shape",
        "floating-pragma",
        "missing-event",
        "old-compiler",
        "parse",
        "report-cap",
        "rtl-override",
      ].sort(),
    );
  });

  it("returns [] for every not-PoC-able detector — no direct map, no category fallback", () => {
    for (const detector of POC_NOT_POCABLE_DETECTORS) {
      assert.deepEqual(
        pick(detector, "high", 3),
        [],
        `${detector} must select no template`,
      );
    }
  });

  it("keeps the invariant: no not-PoC-able detector is directly mapped", () => {
    for (const detector of POC_NOT_POCABLE_DETECTORS) {
      assert.equal(
        POC_FALLBACK_BY_DETECTOR[detector],
        undefined,
        `${detector} is both not-PoC-able and mapped`,
      );
    }
  });

  it("rtl-override (the audit's headline case) no longer borrows the open-drain harness", () => {
    // Before the fix this returned 06-open-drain, 07, 07b via the
    // access_control category.
    assert.deepEqual(pick("rtl-override", "high", 3), []);
  });

  it("a not-PoC-able finding contributes nothing and does not crowd out a real one", () => {
    const picks = filesOf(
      selectPocFallbacks(
        [
          { detector: "rtl-override", severity: "high" },
          { detector: "reentrancy", severity: "high" },
        ],
        3,
      ),
    );
    assert.deepEqual(picks, [
      "01-reentrancy-classic.t.sol",
      "02-reentrancy-cross-function.t.sol",
      "03-reentrancy-erc777.t.sol",
    ]);
  });

  it("default-visibility and bytecode-proxy keep their mechanism-correct harnesses", () => {
    // Both were listed not-PoC-able while also having direct maps — the
    // contradiction is resolved in favor of the maps: 07b judges the
    // mis-scoped function's state change, 11 the uninitialized
    // implementation behind the proxy.
    assert.deepEqual(pick("default-visibility", "medium", 1), [
      "07b-unprotected-visibility.t.sol",
    ]);
    assert.deepEqual(pick("bytecode-proxy", "low", 1), [
      "11-proxy-uninitialized-implementation.t.sol",
    ]);
  });
});

describe("detector map ordering and membership", () => {
  it("locked-ether runs the dedicated harness (29) before owner-rug (28)", () => {
    assert.deepEqual(POC_FALLBACK_BY_DETECTOR["locked-ether"], [
      "29-locked-ether.t.sol",
      "28-centralization-owner-rug.t.sol",
    ]);
    assert.deepEqual(pick("locked-ether", "high", 1), ["29-locked-ether.t.sol"]);
  });

  it("gas-estimator-dos maps directly to the generic DoS harness (39)", () => {
    // The detector (bytecode.ts, SWC-128) flags unbounded storage access
    // in a loop — loop gas growth, which is 39's mechanism. Unmapped, it
    // inherited the denial_of_service category with strict-balance (21),
    // a different mechanism, on top.
    assert.deepEqual(POC_FALLBACK_BY_DETECTOR["gas-estimator-dos"], [
      "39-dos.t.sol",
    ]);
    assert.deepEqual(pick("gas-estimator-dos", "medium", 1), ["39-dos.t.sol"]);
  });

  it("erc20-unchecked maps only to the mechanism-correct template (14), not 37", () => {
    assert.deepEqual(POC_FALLBACK_BY_DETECTOR["erc20-unchecked"], [
      "14-erc20-unchecked-bool.t.sol",
    ]);
  });

  it("35 flash-loan is mapped to none of the oracle / slippage detectors", () => {
    for (const detector of ["oracle-spot", "balance-as-price", "slippage"]) {
      assert.ok(
        !(POC_FALLBACK_BY_DETECTOR[detector] ?? []).includes(
          "35-flash-loan-generic.t.sol",
        ),
        `35 must not be mapped to ${detector}`,
      );
    }
    assert.deepEqual(POC_FALLBACK_BY_DETECTOR["oracle-spot"], [
      "16-oracle-manipulation.t.sol",
    ]);
    assert.deepEqual(POC_FALLBACK_BY_DETECTOR["slippage"], [
      "17-slippage-sandwich.t.sol",
    ]);
  });

  it("an ordinary mapped detector still selects its harness (selection not broken)", () => {
    assert.deepEqual(pick("unprotected-ether", "high", 1), [
      "06-open-drain.t.sol",
    ]);
    assert.deepEqual(pick("token-drain", "high", 1), [
      "46-token-rescue.t.sol",
    ]);
  });

  it("timestamp's primary is the dedicated timestamp harness (45), not the randomness harness (20)", () => {
    // Deliberate index.json entry order: 45-timestamp-dependence sits
    // ahead of 20-chain-randomness-timestamp in the fallbacks array, so
    // the generator emits it first for the two detectors they share
    // (timestamp, bytecode-timestamp). 45 is the dedicated timestamp
    // harness; 20 stays primary where it belongs — weak-randomness,
    // which only it claims. Do not "tidy" the entry order back.
    assert.deepEqual(POC_FALLBACK_BY_DETECTOR["timestamp"], [
      "45-timestamp-dependence.t.sol",
      "20-chain-randomness-timestamp.t.sol",
    ]);
    assert.deepEqual(POC_FALLBACK_BY_DETECTOR["bytecode-timestamp"], [
      "45-timestamp-dependence.t.sol",
      "20-chain-randomness-timestamp.t.sol",
    ]);
    assert.deepEqual(POC_FALLBACK_BY_DETECTOR["weak-randomness"], [
      "20-chain-randomness-timestamp.t.sol",
    ]);
  });
});

// ---------------------------------------------------------------------
// Selection ratchet (G2): for every ai-poc-proof manifest type, mirror
// EXACTLY how the proof suite selects — run.mjs builds the finding as
// { detector: t.detector, severity: "critical" } and prompt-path.ts
// records selectPocFallbacks([finding], 1)[0] as the top pick — and
// assert the type's OWN template is that top pick. A type whose
// template is not top-1 for the detector the manifest pairs it with
// means the suite (and any single-template consumer) reaches for a
// different mechanism than the one the type exists to prove.
//
// Two exemption classes, both explicit — nothing is silently skipped:
//
// - NO_HOME_DETECTOR: the template's index.json entry declares
//   detectors: [] BY DESIGN (the verdict-integrity batch removed its
//   mappings because no analyzer detector describes its mechanism).
//   The manifest pairs the type with the nearest detector so the suite
//   can still run it; the correct behavior is that the mechanism-
//   correct template for THAT detector stays top pick and this
//   template stays unmapped.
// - SHARED_DETECTOR: the analyzer emits ONE detector for a whole
//   family, so several sibling templates share the map and exactly one
//   can be primary. The ratchet asserts the weaker invariant for these:
//   the type's own template IS in the detector's map, and the top pick
//   is the named family primary. (40 is in this class pending a policy
//   call: whether balance-as-price's primary should be the generic
//   price-manipulation harness 16 or the ERC4626 share-inflation
//   specialization 40 is a judgment the map alone cannot make — the
//   exemption records the current primary, it does not bless it.)
// ---------------------------------------------------------------------

type ManifestType = { id: string; file: string; detector: string };
const manifest = JSON.parse(
  readFileSync(
    new URL("../../../scripts/ai-poc-proof/manifest.json", import.meta.url),
    "utf8",
  ),
) as { types: ManifestType[] };

const topPickFor = (detector: string): string | null =>
  selectPocFallbacks([{ detector, severity: "critical" }], 1)[0]?.file ?? null;

const NO_HOME_DETECTOR: Record<string, { expectedTop: string; reason: string }> = {
  "35-flash-loan-generic": {
    expectedTop: "16-oracle-manipulation.t.sol",
    reason:
      "35's detectors: [] is deliberate (verdict-integrity batch): no analyzer detector describes a generic flash-loan harness, and mapping it to the oracle detectors let it manufacture verdicts there. The manifest pairs it with oracle-spot, whose mechanism-correct primary is 16.",
  },
  "37-approval-abuse": {
    expectedTop: "14-erc20-unchecked-bool.t.sol",
    reason:
      "37's detectors: [] is deliberate (verdict-integrity batch): no analyzer detector describes approval abuse, and its old erc20-unchecked mapping borrowed 14's detector. The manifest pairs it with erc20-unchecked, whose only mechanism-correct template is 14.",
  },
};

const SHARED_DETECTOR: Record<string, { primary: string; reason: string }> = {
  "02-reentrancy-cross-function": {
    primary: "01-reentrancy-classic.t.sol",
    reason:
      "The analyzer emits a single `reentrancy` detector for every reentrancy variant; 01 is the family primary and 02/03/04 are sibling specializations in the same map.",
  },
  "03-reentrancy-erc777": {
    primary: "01-reentrancy-classic.t.sol",
    reason:
      "Shared `reentrancy` detector (see 02): the ERC777 callback specialization sits behind the classic primary.",
  },
  "04-reentrancy-erc721": {
    primary: "01-reentrancy-classic.t.sol",
    reason:
      "Shared `reentrancy` detector (see 02): the ERC721 mint-callback specialization sits behind the classic primary.",
  },
  "11-proxy-uninitialized-implementation": {
    primary: "08-unprotected-initializer.t.sol",
    reason:
      "Shares `unprotected-initializer` with 08, the generic initializer harness; 11 is the proxy-specialized second pick (and is top-1 for its other home detector, bytecode-proxy — asserted separately below).",
  },
  "36-merkle-double-claim": {
    primary: "06-open-drain.t.sol",
    reason:
      "36 claims only `unprotected-ether`; no merkle/claim detector exists in the analyzer, and 06 open-drain is the mechanism primary for unprotected ether movement (pinned in the map tests above).",
  },
  "38-governance-flash-vote": {
    primary: "28-centralization-owner-rug.t.sol",
    reason:
      "Shares `centralization` with 28, the generic centralization/owner-risk primary; no governance-specific detector exists in the analyzer.",
  },
  "39-dos": {
    primary: "13-unchecked-call.t.sol",
    reason:
      "The manifest pairs 39 with `unchecked-call`, whose primary is 13. 39's own home detector is gas-estimator-dos, where it IS the sole top pick (pinned in the map tests above).",
  },
  "40-erc4626-inflation": {
    primary: "16-oracle-manipulation.t.sol",
    reason:
      "Shares `balance-as-price` with 16, the generic spot/balance price-manipulation harness. Whether the ERC4626 share-inflation specialization should be primary for balance-as-price findings is an open policy question; this records the current primary without deciding it.",
  },
};

describe("selection ratchet — every ai-poc-proof type's own template is the top pick for its detector", () => {
  it("covers every manifest type exactly once (exemption tables cannot rot silently)", () => {
    assert.equal(manifest.types.length, 47);
    const ids = new Set(manifest.types.map((t) => t.id));
    for (const id of Object.keys(NO_HOME_DETECTOR)) {
      assert.ok(ids.has(id), `NO_HOME_DETECTOR names ${id}, which is not a manifest type`);
    }
    for (const id of Object.keys(SHARED_DETECTOR)) {
      assert.ok(ids.has(id), `SHARED_DETECTOR names ${id}, which is not a manifest type`);
    }
  });

  it("types with a home detector: own template is top pick", () => {
    for (const t of manifest.types) {
      if (NO_HOME_DETECTOR[t.id] || SHARED_DETECTOR[t.id]) continue;
      assert.equal(
        topPickFor(t.detector),
        t.file,
        `${t.id}: detector ${t.detector} must top-pick its own template ${t.file}`,
      );
    }
  });

  it("no-home-detector types stay unmapped and the paired detector keeps its correct primary", () => {
    for (const [id, exempt] of Object.entries(NO_HOME_DETECTOR)) {
      const t = manifest.types.find((x) => x.id === id);
      assert.ok(t, `${id} missing from manifest`);
      // The design fact the exemption rests on: the template really does
      // declare no detectors in the catalog.
      const catalogEntry = POC_FALLBACK_CATALOG.find((e) => e.file === t.file);
      assert.ok(catalogEntry, `${t.file} missing from catalog`);
      assert.deepEqual(
        catalogEntry.detectors,
        [],
        `${id}: exemption reason says detectors: [] by design — ${exempt.reason}`,
      );
      assert.equal(
        topPickFor(t.detector),
        exempt.expectedTop,
        `${id}: ${exempt.reason}`,
      );
      assert.ok(
        !(POC_FALLBACK_BY_DETECTOR[t.detector] ?? []).includes(t.file),
        `${id} must not be mapped to ${t.detector}`,
      );
    }
  });

  it("shared-detector types are in their detector's map behind the named family primary", () => {
    for (const [id, shared] of Object.entries(SHARED_DETECTOR)) {
      const t = manifest.types.find((x) => x.id === id);
      assert.ok(t, `${id} missing from manifest`);
      assert.ok(
        (POC_FALLBACK_BY_DETECTOR[t.detector] ?? []).includes(t.file),
        `${id}: own template ${t.file} must be in the ${t.detector} map — ${shared.reason}`,
      );
      assert.equal(
        topPickFor(t.detector),
        shared.primary,
        `${id}: family primary for ${t.detector} — ${shared.reason}`,
      );
    }
  });

  it("11 is top pick for its other home detector (bytecode-proxy)", () => {
    assert.equal(topPickFor("bytecode-proxy"), "11-proxy-uninitialized-implementation.t.sol");
  });
});
