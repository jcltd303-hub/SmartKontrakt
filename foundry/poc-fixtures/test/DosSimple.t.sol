// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {DosSimple} from "../src/DosSimple.sol";
import {DosSimpleFixed} from "../src/DosSimpleFixed.sol";

contract DosSimpleFixtureTest is Test {

    // The dynamic array `listAddresses` lives in storage slot 0; for a dynamic
    // array the slot itself holds the length. We read it directly, since the
    // dataset contract exposes no getter (and we must not add one to the port).
    function _length(address c) internal view returns (uint256) {
        return uint256(vm.load(c, bytes32(uint256(0))));
    }

    // -----------------------------------------------------------------
    // Half 1: the DoS reproduces against the vulnerable port.
    // -----------------------------------------------------------------
    function test_fixtureReproduces() public {
        DosSimple port = new DosSimple();

        // One single external call writes 350 storage slots -> unbounded, gas-heavy work.
        uint256 g0 = gasleft();
        vm.prank(address(0xA11CE));
        bool ok = port.ifillArray();
        uint256 gasUsed = g0 - gasleft();

        assertTrue(ok, "call should succeed");
        assertEq(_length(address(port)), 350, "one call must append 350 entries (unbounded per-call work)");
        // 350 cold SSTOREs cost several million gas: a single participant can
        // occupy a huge fraction of a block. This is the SWC-128 DoS.
        assertGt(gasUsed, 3_000_000, "one call must burn a block-sized amount of gas");
        console.log("DosSimple port gas for one ifillArray():", gasUsed);

        // And the whole list can be destroyed by a griefer crossing the 1500 cap.
        vm.prank(address(0xA11CE));
        port.ifillArray(); // 700
        vm.prank(address(0xA11CE));
        port.ifillArray(); // 1050
        vm.prank(address(0xA11CE));
        port.ifillArray(); // 1400
        vm.prank(address(0xA11CE));
        port.ifillArray(); // 1750 (>=1500 now)
        assertEq(_length(address(port)), 1750, "list grew to 1750");

        vm.prank(address(0xB0B)); // an honest participant
        bool ok2 = port.ifillArray();
        assertFalse(ok2, "honest call now hits the else branch");
        assertEq(_length(address(port)), 0, "griefer forced a wipe of ALL records -> denial of service");
    }

    // -----------------------------------------------------------------
    // Half 2: the SAME attack does not fire against the fixed variant.
    // -----------------------------------------------------------------
    function test_fixtureDoesNotReproduce() public {
        DosSimpleFixed fixedC = new DosSimpleFixed();

        uint256 g0 = gasleft();
        vm.prank(address(0xA11CE));
        fixedC.ifillArray();
        uint256 gasUsed = g0 - gasleft();

        assertEq(_length(address(fixedC)), 1, "fixed: one call appends exactly one entry");
        assertLt(gasUsed, 500_000, "fixed: one call is cheap -> cannot exhaust the gas limit");
        console.log("DosSimpleFixed gas for one ifillArray():", gasUsed);

        // The griefer tries the same bloat-and-wipe attack.
        for (uint256 i = 0; i < 4; i++) {
            vm.prank(address(0xA11CE));
            fixedC.ifillArray();
        }
        assertEq(_length(address(fixedC)), 5, "fixed: records accumulate, never wiped");
        vm.prank(address(0xB0B));
        bool ok = fixedC.ifillArray();
        assertTrue(ok, "fixed: honest call still succeeds");
        assertEq(_length(address(fixedC)), 6, "fixed: no denial of service");
    }
}
