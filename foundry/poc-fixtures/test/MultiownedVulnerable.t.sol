// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MultiownedVulnerable, MultiownedVulnerableTestContract} from "../src/MultiownedVulnerable.sol";
import {MultiownedVulnerableFixed, MultiownedVulnerableFixedTestContract} from "../src/MultiownedVulnerableFixed.sol";

// Differential fixture for the SWC-105 unprotected-critical-function bug.
// `newOwner` on the vulnerable contract is `external` with NO `onlyOwner`
// modifier, so any caller can add itself as an owner. The fixed variant adds
// the missing `onlyOwner` check.
contract MultiownedVulnerableFixtureTest is Test {
    address internal attacker;

    function setUp() public {
        attacker = makeAddr("attacker");
    }

    function test_fixtureReproduces() public {
        MultiownedVulnerableTestContract c = new MultiownedVulnerableTestContract();
        vm.deal(address(c), 1 ether);
        assertEq(c.owners(attacker), address(0), "attacker is not an owner initially");

        // No access control on newOwner: the attacker promotes itself.
        vm.prank(attacker);
        c.newOwner(attacker);
        assertEq(c.owners(attacker), attacker, "attacker added itself as owner (missing onlyOwner)");

        // Being an owner now, the attacker can drain the contract.
        vm.prank(attacker);
        c.withdrawAll();
        assertEq(attacker.balance, 1 ether, "attacker drained the contract");
        assertEq(address(c).balance, 0, "contract emptied");
    }

    function test_fixtureDoesNotReproduce() public {
        MultiownedVulnerableFixedTestContract c = new MultiownedVulnerableFixedTestContract();
        vm.deal(address(c), 1 ether);

        vm.prank(attacker);
        vm.expectRevert();
        c.newOwner(attacker);

        assertEq(c.owners(attacker), address(0), "attacker still not an owner: onlyOwner blocked it");
        assertEq(address(c).balance, 1 ether, "funds untouched");
    }
}
