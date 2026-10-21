// SPDX-License-Identifier: MIT
/*
 * FIXED VARIANT of dataset/arithmetic/overflow_simple_add.sol
 * (smartbugs/smartbugs-curated)
 *
 * Standard remediation: rely on Solidity >= 0.8 checked arithmetic (the
 * `unchecked` block is removed), so `add` reverts on overflow instead of
 * wrapping.
 */
pragma solidity ^0.8.24;

contract OverflowSimpleAddFixed {
    uint256 public balance = 1;

    function add(uint256 deposit) public {
        // <yes> <report> ARITHMETIC
        balance += deposit;
    }
}
