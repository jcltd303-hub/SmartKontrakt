// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {IntegerOverflowAdd} from "../src/IntegerOverflowAdd.sol";
import {IntegerOverflowAddFixed} from "../src/IntegerOverflowAddFixed.sol";

/// @title Differential fixture for dataset/arithmetic/integer_overflow_add.sol
contract IntegerOverflowAddFixtureTest is Test {
    address internal constant ATTACKER = address(0xA11CE);

    /// @notice Attack DOES fire on the vulnerable port: 1 + type(uint256).max wraps to 0.
    function test_fixtureReproducesOverflow() public {
        IntegerOverflowAdd target = new IntegerOverflowAdd();
        assertEq(target.count(), 1);

        vm.prank(ATTACKER);
        target.run(type(uint256).max);

        // wrap-around: 1 + (2**256 - 1) == 0
        assertEq(target.count(), 0);
    }

    /// @notice Same attack does NOT fire on the fixed variant: checked add reverts.
    function test_fixtureDoesNotReproduceOverflow() public {
        IntegerOverflowAddFixed target = new IntegerOverflowAddFixed();
        assertEq(target.count(), 1);

        vm.prank(ATTACKER);
        vm.expectRevert();
        target.run(type(uint256).max);

        // state untouched because the overflow reverted
        assertEq(target.count(), 1);
    }
}
