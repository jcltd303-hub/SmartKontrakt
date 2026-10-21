// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {UncheckedReturnValue} from "../src/UncheckedReturnValue.sol";
import {UncheckedReturnValueFixed} from "../src/UncheckedReturnValueFixed.sol";

/// @dev Helper: a callee whose receive() reverts on demand, so a low-level call
///      with empty calldata fails. Prefixed with the fixture name.
contract UncheckedReturnValueTarget {
    uint256 public executed;
    bool public shouldRevert;

    constructor(bool _shouldRevert) {
        shouldRevert = _shouldRevert;
    }

    receive() external payable {
        require(!shouldRevert, "target reverted");
        executed++;
    }
}

/// @title Differential fixture for dataset/unchecked_low_level_calls/unchecked_return_value.sol
contract UncheckedReturnValueFixtureTest is Test {
    address internal constant ATTACKER = address(0xD00D);

    /// @notice Attack DOES fire: the failing low-level call is not noticed, so the
    ///         vulnerable function returns normally while the callee never ran.
    function test_fixtureReproducesUncheckedReturn() public {
        UncheckedReturnValue target = new UncheckedReturnValue();
        UncheckedReturnValueTarget callee = new UncheckedReturnValueTarget(true);

        // sanity: the raw low-level call genuinely fails
        (bool ok, ) = address(callee).call("");
        assertFalse(ok);

        // vulnerable path: failure is swallowed, no revert propagates
        vm.prank(ATTACKER);
        target.callnotchecked(address(callee));

        assertEq(callee.executed(), 0);
    }

    /// @notice Same attack does NOT fire on the fixed variant: the checked call
    ///         reverts when the callee fails.
    function test_fixtureDoesNotReproduceUncheckedReturn() public {
        UncheckedReturnValueFixed target = new UncheckedReturnValueFixed();
        UncheckedReturnValueTarget callee = new UncheckedReturnValueTarget(true);

        (bool ok, ) = address(callee).call("");
        assertFalse(ok);

        vm.prank(ATTACKER);
        vm.expectRevert();
        target.callnotchecked(address(callee));

        assertEq(callee.executed(), 0);
    }
}
