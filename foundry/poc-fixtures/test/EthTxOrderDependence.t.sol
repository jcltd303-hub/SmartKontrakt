// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {EthTxOrderDependence} from "../src/EthTxOrderDependence.sol";
import {EthTxOrderDependenceFixed} from "../src/EthTxOrderDependenceFixed.sol";

contract EthTxOrderDependenceFixtureTest is Test {

    address constant OWNER = address(0x0117);
    address constant ATTACKER = address(0xA11CE);

    // -----------------------------------------------------------------
    // Half 1: the front-running reproduces against the vulnerable port.
    // -----------------------------------------------------------------
    function test_fixtureReproduces() public {
        vm.deal(OWNER, 10 ether);
        vm.deal(ATTACKER, 1 ether);

        vm.prank(OWNER);
        EthTxOrderDependence c = new EthTxOrderDependence();

        // Owner sets a reward of 1 ether.
        vm.prank(OWNER);
        c.setReward{value: 1 ether}();
        assertEq(c.reward(), 1 ether);

        // Owner prepares a NEW setReward{2 ether}. The attacker front-runs it
        // with claimReward, taking the pending reward first.
        vm.prank(ATTACKER);
        c.claimReward(0);

        assertEq(ATTACKER.balance, 2 ether, "attacker stole the 1 ether reward by front-running");
        assertTrue(c.claimed(), "claimed flag set -> owner's next deposit is bricked");

        // The owner's deposit can no longer land.
        vm.prank(OWNER);
        vm.expectRevert();
        c.setReward{value: 2 ether}();
    }

    // -----------------------------------------------------------------
    // Half 2: the SAME attack does not fire against the fixed variant.
    // -----------------------------------------------------------------
    function test_fixtureDoesNotReproduce() public {
        vm.deal(OWNER, 10 ether);
        vm.deal(ATTACKER, 1 ether);

        vm.prank(OWNER);
        EthTxOrderDependenceFixed c = new EthTxOrderDependenceFixed();

        vm.prank(OWNER);
        c.setReward{value: 1 ether}();
        assertEq(c.reward(), 1 ether);

        // The attacker tries the same atomic front-run: commit and reveal in the
        // SAME block (i.e. react to the pending setReward).
        bytes32 h = keccak256(abi.encodePacked(uint256(0), bytes32(0)));
        vm.prank(ATTACKER);
        c.commitClaim(h);
        vm.prank(ATTACKER);
        vm.expectRevert(); // commit and reveal must be in separate blocks
        c.claimReward(0, bytes32(0));

        // The owner's deposit lands fine, nothing was stolen.
        vm.prank(OWNER);
        c.setReward{value: 2 ether}();
        assertEq(c.reward(), 2 ether, "fixed: owner can update the reward");
        assertFalse(c.claimed(), "fixed: claim did not fire");
        assertEq(ATTACKER.balance, 1 ether, "fixed: attacker gained nothing");
    }
}
