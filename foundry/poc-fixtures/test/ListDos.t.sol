// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {ListDos} from "../src/ListDos.sol";
import {ListDosFixed} from "../src/ListDosFixed.sol";

contract ListDosFixtureTest is Test {

    // -----------------------------------------------------------------
    // Half 1: the DoS reproduces against the vulnerable port.
    // -----------------------------------------------------------------
    function test_fixtureReproduces() public {
        ListDos gov = new ListDos();

        address alice = address(0xA11CE);
        address bob = address(0xB0B);
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);

        // Two creditors lend 1 ether each (>= 1e18 keeps the system alive).
        vm.prank(alice);
        gov.lendGovernmentMoney{value: 1 ether}(address(0));
        vm.prank(bob);
        gov.lendGovernmentMoney{value: 1 ether}(address(0));
        assertEq(gov.getCreditorAddresses().length, 2, "two creditor records exist");

        // After 12h of inactivity ANY caller triggers the breakdown branch.
        vm.warp(block.timestamp + 43201);
        vm.prank(address(0xDEAD)); // a griefer, no special role needed
        gov.lendGovernmentMoney{value: 0}(address(0));

        // The griefer has wiped every creditor's record -> denial of service.
        assertEq(gov.getCreditorAddresses().length, 0, "all creditor addresses destroyed");
        assertEq(gov.getCreditorAmounts().length, 0, "all creditor amounts destroyed");
        console.log("ListDos: creditor records wiped by a single griefer");
    }

    // -----------------------------------------------------------------
    // Half 2: the SAME attack does not fire against the fixed variant.
    // -----------------------------------------------------------------
    function test_fixtureDoesNotReproduce() public {
        ListDosFixed gov = new ListDosFixed();

        address alice = address(0xA11CE);
        address bob = address(0xB0B);
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);

        vm.prank(alice);
        gov.lendGovernmentMoney{value: 1 ether}(address(0));
        vm.prank(bob);
        gov.lendGovernmentMoney{value: 1 ether}(address(0));
        assertEq(gov.getCreditorAddresses().length, 2);

        // Same griefer, same trigger.
        vm.warp(block.timestamp + 43201);
        vm.prank(address(0xDEAD));
        gov.lendGovernmentMoney{value: 0}(address(0));

        // FIX: records survive the breakdown.
        assertEq(gov.getCreditorAddresses().length, 2, "fixed: creditor addresses preserved");
        assertEq(gov.getCreditorAmounts().length, 2, "fixed: creditor amounts preserved");
    }
}
