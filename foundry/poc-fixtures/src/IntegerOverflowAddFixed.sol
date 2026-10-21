// SPDX-License-Identifier: MIT
/*
 * FIXED VARIANT of dataset/arithmetic/integer_overflow_add.sol
 * (smartbugs/smartbugs-curated)
 *
 * Standard remediation: rely on Solidity >= 0.8 checked arithmetic (the
 * `unchecked` block is removed). The addition now reverts on overflow instead
 * of wrapping, so `run(type(uint256).max)` on a count of 1 reverts.
 */
pragma solidity ^0.8.24;

contract IntegerOverflowAddFixed {
    uint256 public count = 1;

    function run(uint256 input) public {
        // <yes> <report> ARITHMETIC
        count += input;
    }
}
