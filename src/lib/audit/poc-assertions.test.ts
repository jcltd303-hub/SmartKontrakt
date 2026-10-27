import test from "node:test";
import assert from "node:assert/strict";

import { assertionFreeReason, countAssertions } from "./poc-outcome.ts";

/**
 * A green suite is not evidence (2026-10-27).
 *
 * Six tests passed on a live run while proving nothing: test_exploit logged
 * "drained from target: 0" and "INCONCLUSIVE", the malleability and replay tests
 * were pure (solc said so), and the rest console.logged findings. Only the
 * INCONCLUSIVE wording — model self-report — stopped that run being archived as a
 * pass.
 */

const SCAFFOLD = `
contract PoC is Test {
    function test_exploit() public {
        (bool ok,) = target.call(abi.encodeWithSignature("refundBet()"));
        console.log("refundBet call succeeded:", ok);
        console.log("drained from target: 0");
        console.log("INCONCLUSIVE: cannot create a bet without a valid signature");
    }
}`;

const REPORT_ONLY = `
contract PoC is Test {
    function test_increaseJackpot_overflow() public {
        console.log("Finding #4 [MEDIUM]: increaseJackpot uses unchecked += on uint128");
        console.log("If jackpotSize + increaseAmount overflows uint128, it wraps");
    }
}`;

const REAL = `
contract PoC is Test {
    function test_exploit() public {
        uint256 before = address(attacker).balance;
        vm.prank(attacker);
        target.refundBet();
        assertGt(address(attacker).balance, before, "attacker did not profit");
    }
}`;

test("a harness that only logs is not a proof", () => {
  assert.equal(countAssertions(SCAFFOLD), 0);
  assert.match(assertionFreeReason(SCAFFOLD) ?? "", /cannot fail always passes/);
});

test("console.log findings are not assertions", () => {
  assert.equal(countAssertions(REPORT_ONLY), 0);
  assert.ok(assertionFreeReason(REPORT_ONLY));
});

test("a real exploit test is accepted", () => {
  assert.ok(countAssertions(REAL) > 0);
  assert.equal(assertionFreeReason(REAL), null);
});

test("expectRevert and expectEmit count: they are how a revert test asserts", () => {
  const reverting = `
contract PoC is Test {
    function test_guarded() public {
        vm.expectRevert("not owner");
        target.onlyOwner();
    }
}`;
  assert.equal(assertionFreeReason(reverting), null);
});

test("assertions inside comments or strings do not count", () => {
  const commented = `
contract PoC is Test {
    function test_exploit() public {
        // assertGt(address(attacker).balance, before);
        console.log("assertEq(1, 1)");
    }
}`;
  assert.equal(countAssertions(commented), 0);
});

test("an empty or absent source is left to the other rules", () => {
  assert.equal(assertionFreeReason(""), null);
  assert.equal(assertionFreeReason("contract X {}"), null, "no test functions: that is no_tests, not this");
});

test("a green suite from an assertion-free PoC saves as unadapted, not passed", () => {
  const { savedStatusFromRun } = require("./poc-outcome.ts") as typeof import("./poc-outcome.ts");
  // The exact shape of the 2026-10-27 run: forge exits 0, six tests green, no
  // assertion anywhere. Without the source the INCONCLUSIVE wording happens to save
  // it; with the source the verdict does not depend on wording at all.
  const logs = "[PASS] test_exploit() (gas: 706053)\nSuite result: ok. 6 passed; 0 failed";
  assert.equal(savedStatusFromRun({ status: "passed", logs }), "passed", "wording alone cannot see it");
  assert.equal(savedStatusFromRun({ status: "passed", logs, pocSource: SCAFFOLD }), "unadapted");
  assert.equal(savedStatusFromRun({ status: "passed", logs, pocSource: REAL }), "passed");
});

test("an inconclusive run is failed even when it asserts", () => {
  const { savedStatusFromRun } = require("./poc-outcome.ts") as typeof import("./poc-outcome.ts");
  const logs = "[PASS] test_exploit()\nINCONCLUSIVE: could not reach the pre-state";
  assert.equal(savedStatusFromRun({ status: "passed", logs, pocSource: REAL }), "failed");
});
