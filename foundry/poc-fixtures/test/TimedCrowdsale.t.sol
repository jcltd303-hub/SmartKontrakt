// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {TimedCrowdsale} from "../src/TimedCrowdsale.sol";
import {TimedCrowdsaleFixed} from "../src/TimedCrowdsaleFixed.sol";

contract TimedCrowdsaleFixtureTest is Test {

    address constant PARTICIPANT = address(0xA11CE);

    // -----------------------------------------------------------------
    // Half 1: the time manipulation reproduces against the vulnerable port.
    // -----------------------------------------------------------------
    function test_fixtureReproduces() public {
        TimedCrowdsale sale = new TimedCrowdsale();

        vm.warp(1546300799);
        vm.prank(PARTICIPANT);
        assertFalse(sale.isSaleFinished(), "one second before the deadline");

        // The observable flips with block.timestamp ALONE (a producer can nudge it).
        vm.warp(1546300800);
        vm.prank(PARTICIPANT);
        assertTrue(sale.isSaleFinished(), "timestamp alone finished the sale");
    }

    // -----------------------------------------------------------------
    // Half 2: the SAME attack does not fire against the fixed variant.
    // -----------------------------------------------------------------
    function test_fixtureDoesNotReproduce() public {
        TimedCrowdsaleFixed sale = new TimedCrowdsaleFixed();

        vm.roll(9_999_999);
        // The same timestamp attack:
        vm.warp(1546300800);
        vm.prank(PARTICIPANT);
        assertFalse(sale.isSaleFinished(), "fixed: warping the timestamp does NOT finish the sale");

        // Only the block-number clock decides.
        vm.roll(10_000_000);
        vm.prank(PARTICIPANT);
        assertTrue(sale.isSaleFinished(), "fixed: the block clock finishes the sale");
    }
}
