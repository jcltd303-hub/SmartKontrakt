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
import {
  SMARTBUGS_BY_DETECTOR,
  smartbugsCategoryForDetector,
} from "./smartbugs.ts";

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
//   is the named family primary. (40's place in this class was an open
//   policy question — balance-as-price's primary: the generic harness
//   16 or the ERC4626 specialization 40 — until Jer decided it on
//   2026-10-23: 16 stays primary for balance-as-price; 40 remains the
//   ERC4626 specialist behind it. The exemption now records a decided
//   primary, not a pending one.)
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
      "Shares `balance-as-price` with 16, the generic spot/balance price-manipulation harness. DECIDED by Jer, 2026-10-23: 16 stays primary for balance-as-price; 40 remains the ERC4626 share-inflation specialist behind it.",
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

// ---------------------------------------------------------------------
// Per-DETECTOR mechanism ratchet (full detector audit, 2026-10-24).
//
// The ratchet above pins per-TYPE top picks (the ai-poc-proof manifest
// pairs each template type with one detector). This block pins per-
// DETECTOR behavior for EVERY detector the engine emits — the literal
// `detector:` ids in detect.ts + bytecode.ts + engine.ts, plus the two
// ids bytecode.ts constructs dynamically (the DELEGATECALL/CALLCODE
// ternary). For each detector it asserts, from the templates' own
// mechanism descriptions (index.json scenarios + template @notice
// headers):
//
//   1. TOTALITY: the detector has an explicit SmartBugs category (the
//      smartbugs.ts docstring claims the map is total over the
//      emitted detectors — before this audit `report-cap` (detect.ts)
//      and `parse` (engine.ts) were missing and silently defaulted
//      to "other" in every prompt that labelled them).
//   2. TOP PICK: selectPocFallbacks(detector, 1) is the mechanism-
//      correct dedicated harness, or [] for a not-PoC-able detector.
//      Exactly one detector has no direct map and reaches its pick
//      through the category list: zero-slippage-swap, whose
//      front_running list [17, 43] is its mechanism-correct pair.
//   3. CATEGORY: three detectors whose SmartBugs category contradicted
//      BOTH the category definitions in smartbugs.ts AND their own
//      templates' index labels are pinned to the corrected values:
//      - token-drain: the detector requires a token transfer with NO
//        ACCESS CHECK (SWC-105; remediation is onlyOwner; template 46
//        header: "has no access check"). It involves no low-level
//        call at all — transfer/safeTransfer are high-level ERC-20
//        calls — so unchecked_low_level_calls (defined in
//        smartbugs.ts as an unchecked call()/send() FAILURE) was
//        wrong; access_control is the class.
//      - msg-value-loop: the mechanism is the same msg.value credited
//        per loop iteration (value extraction). denial_of_service is
//        defined as overwhelming computation; template 22's own index
//        label and provenance both say "other".
//      - shadowing: a name-resolution bug (write lands in the shadow
//        variable). access_control is defined as modifier failure /
//        tx.origin use — neither is present; template 33's own index
//        label and provenance both say "other".
// ---------------------------------------------------------------------

function emittedDetectors(): string[] {
  const ids = new Set<string>();
  for (const rel of ["./detect.ts", "./bytecode.ts", "./engine.ts"]) {
    const src = readFileSync(new URL(rel, import.meta.url), "utf8");
    for (const m of src.matchAll(/detector:\s*"([^"]+)"/g)) ids.add(m[1]);
  }
  // bytecode.ts constructs these two dynamically:
  //   detector: deleg > 0 ? "bytecode-delegatecall" : "bytecode-callcode"
  const bytecodeSrc = readFileSync(new URL("./bytecode.ts", import.meta.url), "utf8");
  assert.ok(bytecodeSrc.includes('"bytecode-delegatecall"'), "dynamic bytecode-delegatecall id moved — update the audit set");
  assert.ok(bytecodeSrc.includes('"bytecode-callcode"'), "dynamic bytecode-callcode id moved — update the audit set");
  ids.add("bytecode-delegatecall");
  ids.add("bytecode-callcode");
  return [...ids].sort();
}

/** Detector -> mechanism-correct top pick (null = not-PoC-able, []). */
const EXPECTED_TOP_PICK: Record<string, string | null> = {
  "assembly-param-sstore": "26-assembly-arbitrary-sstore.t.sol",
  "assembly-sstore": "26-assembly-arbitrary-sstore.t.sol",
  "balance-as-price": "16-oracle-manipulation.t.sol",
  "bytecode-callcode": "10-delegatecall-takeover.t.sol",
  "bytecode-create2": "41-create2-metamorphic.t.sol",
  "bytecode-delegatecall": "10-delegatecall-takeover.t.sol",
  "bytecode-metadata": null,
  "bytecode-origin": "09-tx-origin-phishing.t.sol",
  "bytecode-proxy": "11-proxy-uninitialized-implementation.t.sol",
  "bytecode-reentrancy-shape": null,
  "bytecode-selfdestruct": "12-selfdestruct.t.sol",
  "bytecode-timestamp": "45-timestamp-dependence.t.sol",
  "bytecode-unchecked-call": "13-unchecked-call.t.sol",
  centralization: "28-centralization-owner-rug.t.sol",
  "default-visibility": "07b-unprotected-visibility.t.sol",
  delegatecall: "10-delegatecall-takeover.t.sol",
  "div-before-mul": "24-div-before-mul.t.sol",
  "encode-packed": "25-encode-packed-collision.t.sol",
  "erc20-unchecked": "14-erc20-unchecked-bool.t.sol",
  "eth-gas-stipend": "31-gas-assumptions.t.sol",
  extcodesize: "27-extcodesize-bypass.t.sol",
  "fee-on-transfer": "15-fee-on-transfer.t.sol",
  "floating-pragma": null,
  "gas-estimator-dos": "39-dos.t.sol",
  // 2026 incident classes (2026-10-27): one harness per class, each modelled
  // on the published post-mortem rather than a SmartBugs port.
  "hook-callback-auth": "47-hook-callback-auth.t.sol",
  "calldata-offset-auth": "48-calldata-offset-auth.t.sol",
  "eoa-only-guard": "49-eoa-only-guard.t.sol",
  "public-key-account-trust": "50-public-key-account-trust.t.sol",
  "unauthenticated-batch-call": "51-unauthenticated-batch-call.t.sol",
  "self-attested-auth": "52-self-attested-auth.t.sol",
  // D2 / D3 (2026-10-27, the games work): settlement optionality is the free
  // option and gets a harness; registry-dispatched logic is an analysis
  // requirement (read the sub-contract), so it is not-PoC-able by design.
  "settlement-optionality": "53-settlement-optionality.t.sol",
  "registry-dispatched-logic": null,
  // 2021-2025 incident classes (2026-10-27, the six-year sweep).
  "arbitrary-dispatch-call": "54-arbitrary-dispatch-call.t.sol",
  "bridge-message-auth": "55-bridge-message-auth.t.sol",
  "governance-live-voting-power": "56-governance-live-voting-power.t.sol",
  "ecrecover-zero": "57-ecrecover-zero.t.sol",
  "oracle-staleness": "58-oracle-staleness.t.sol",
  "hardcoded-gas": "31-gas-assumptions.t.sol",
  "locked-ether": "29-locked-ether.t.sol",
  "missing-event": null,
  "msg-value-loop": "22-msg-value-loop.t.sol",
  "old-compiler": null,
  "oracle-spot": "16-oracle-manipulation.t.sol",
  parse: null,
  "private-secret": "34-private-secret-onchain.t.sol",
  "read-only-reentrancy": "05-reentrancy-read-only.t.sol",
  reentrancy: "01-reentrancy-classic.t.sol",
  "report-cap": null,
  "rtl-override": null,
  selfdestruct: "12-selfdestruct.t.sol",
  shadowing: "33-shadowing-mismatch.t.sol",
  "signature-malleability": "19-signature-malleability.t.sol",
  "signature-replay": "18-signature-replay.t.sol",
  slippage: "17-slippage-sandwich.t.sol",
  "storage-gap": "32-storage-collision-upgrade.t.sol",
  "strict-balance": "21-strict-balance-dos.t.sol",
  timestamp: "45-timestamp-dependence.t.sol",
  "token-drain": "46-token-rescue.t.sol",
  "tx-origin": "09-tx-origin-phishing.t.sol",
  "unchecked-block": "23-unchecked-arithmetic-wrap.t.sol",
  "unchecked-call": "13-unchecked-call.t.sol",
  "unprotected-admin": "07-unprotected-admin.t.sol",
  "unprotected-ether": "06-open-drain.t.sol",
  "unprotected-initializer": "08-unprotected-initializer.t.sol",
  "weak-randomness": "20-chain-randomness-timestamp.t.sol",
  "zero-address": "30-zero-address-brick.t.sol",
  "zero-slippage-swap": "17-slippage-sandwich.t.sol",
};

describe("per-detector mechanism ratchet — every emitted detector", () => {
  it("the audit table covers exactly the emitted detector set (no silent rot)", () => {
    assert.deepEqual(Object.keys(EXPECTED_TOP_PICK).sort(), emittedDetectors());
  });

  it("every emitted detector has an explicit SmartBugs category (totality)", () => {
    for (const detector of emittedDetectors()) {
      assert.ok(
        SMARTBUGS_BY_DETECTOR[detector],
        `${detector} is emitted by the engine but has no SMARTBUGS_BY_DETECTOR entry — prompts silently label it "other"`,
      );
    }
  });

  it("every emitted detector's top pick is its mechanism-correct harness (or [] when not-PoC-able)", () => {
    for (const [detector, expected] of Object.entries(EXPECTED_TOP_PICK)) {
      assert.equal(
        topPickFor(detector),
        expected,
        `${detector}: top pick must be ${expected ?? "[] (not-PoC-able)"}`,
      );
    }
  });

  it("zero-slippage-swap is the one category-fallthrough detector, and its list is mechanism-correct", () => {
    // No direct map in index.json (17 claims only `slippage`); selection
    // falls through to the front_running category list [17, 43].
    assert.equal(POC_FALLBACK_BY_DETECTOR["zero-slippage-swap"], undefined);
    assert.deepEqual(pick("zero-slippage-swap", "high", 3), [
      "17-slippage-sandwich.t.sol",
      "43-front-running.t.sol",
    ]);
    // And it is the ONLY emitted, PoC-able detector in that position.
    for (const detector of emittedDetectors()) {
      if (detector === "zero-slippage-swap") continue;
      if (POC_NOT_POCABLE_DETECTORS.includes(detector)) continue;
      assert.ok(
        POC_FALLBACK_BY_DETECTOR[detector]?.length,
        `${detector} unexpectedly has no direct map — it would inherit its whole category list`,
      );
    }
  });

  it("category corrections: token-drain is access_control, msg-value-loop and shadowing are other", () => {
    assert.equal(smartbugsCategoryForDetector("token-drain"), "access_control");
    assert.equal(smartbugsCategoryForDetector("msg-value-loop"), "other");
    assert.equal(smartbugsCategoryForDetector("shadowing"), "other");
    // The corrected categories agree with the templates' own index labels.
    for (const [detector, file] of [
      ["token-drain", "46-token-rescue.t.sol"],
      ["msg-value-loop", "22-msg-value-loop.t.sol"],
      ["shadowing", "33-shadowing-mismatch.t.sol"],
    ] as const) {
      const entry = POC_FALLBACK_CATALOG.find((e) => e.file === file);
      assert.equal(entry?.smartbugs, smartbugsCategoryForDetector(detector), `${detector} vs ${file}`);
    }
    // Selection is unchanged for all three: the direct maps still rule.
    assert.equal(topPickFor("token-drain"), "46-token-rescue.t.sol");
    assert.equal(topPickFor("msg-value-loop"), "22-msg-value-loop.t.sol");
    assert.equal(topPickFor("shadowing"), "33-shadowing-mismatch.t.sol");
  });
});
