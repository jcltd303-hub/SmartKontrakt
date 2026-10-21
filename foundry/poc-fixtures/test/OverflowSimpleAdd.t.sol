// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {OverflowSimpleAdd} from "../src/OverflowSimpleAdd.sol";
import {OverflowSimpleAddFixed} from "../src/OverflowSimpleAddFixed.sol";

/// @title Differential fixture for dataset/arithmetic/overflow_simple_add.sol
contract OverflowSimpleAddFixtureTest is Test {
    address internal constant ATTACKER = address(0xB0B);

    /// @notice Attack DOES fire on the vulnerable port: 1 + type(uint256).max wraps to 0.
    function test_fixtureReproducesOverflow() public {
        OverflowSimpleAdd target = new OverflowSimpleAdd();
        assertEq(target.balance(), 1);

        vm.prank(ATTACKER);
        target.add(type(uint256).max);

        assertEq(target.balance(), 0);
    }

    /// @notice Same attack does NOT fire on the fixed variant: checked add reverts.
    function test_fixtureDoesNotReproduceOverflow() public {
        OverflowSimpleAddFixed target = new OverflowSimpleAddFixed();
        assertEq(target.balance(), 1);

        vm.prank(ATTACKER);
        vm.expectRevert();
        target.add(type(uint256).max);

        assertEq(target.balance(), 1);
    }
}
