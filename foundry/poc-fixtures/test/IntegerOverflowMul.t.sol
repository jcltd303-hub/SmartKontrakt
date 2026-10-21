// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {IntegerOverflowMul} from "../src/IntegerOverflowMul.sol";
import {IntegerOverflowMulFixed} from "../src/IntegerOverflowMulFixed.sol";

/// @title Differential fixture for dataset/arithmetic/integer_overflow_mul.sol
contract IntegerOverflowMulFixtureTest is Test {
    address internal constant ATTACKER = address(0xC0FFEE);

    /// @notice Attack DOES fire on the vulnerable port: 2 * 2**255 wraps to 0.
    function test_fixtureReproducesOverflow() public {
        IntegerOverflowMul target = new IntegerOverflowMul();
        assertEq(target.count(), 2);

        vm.prank(ATTACKER);
        target.run(2 ** 255);

        // wrap-around: 2 * 2**255 == 2**256 == 0 (mod 2**256)
        assertEq(target.count(), 0);
    }

    /// @notice Same attack does NOT fire on the fixed variant: checked mul reverts.
    function test_fixtureDoesNotReproduceOverflow() public {
        IntegerOverflowMulFixed target = new IntegerOverflowMulFixed();
        assertEq(target.count(), 2);

        vm.prank(ATTACKER);
        vm.expectRevert();
        target.run(2 ** 255);

        assertEq(target.count(), 2);
    }
}
