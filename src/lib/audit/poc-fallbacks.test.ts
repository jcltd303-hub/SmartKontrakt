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
import {
  POC_FALLBACK_BY_DETECTOR,
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
});
