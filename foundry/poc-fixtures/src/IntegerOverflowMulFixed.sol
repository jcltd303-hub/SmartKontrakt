// SPDX-License-Identifier: MIT
/*
 * FIXED VARIANT of dataset/arithmetic/integer_overflow_mul.sol
 * (smartbugs/smartbugs-curated)
 *
 * Standard remediation: rely on Solidity >= 0.8 checked arithmetic (the
 * `unchecked` block is removed), so `run` reverts on overflow instead of
 * wrapping.
 */
pragma solidity ^0.8.24;

contract IntegerOverflowMulFixed {
    uint256 public count = 2;

    function run(uint256 input) public {
        // <yes> <report> ARITHMETIC
        count *= input;
    }
}
