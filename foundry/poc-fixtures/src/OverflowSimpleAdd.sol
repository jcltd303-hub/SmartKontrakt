// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 * Dataset: smartbugs/smartbugs-curated
 * Dataset path: dataset/arithmetic/overflow_simple_add.sol
 * @source: https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-101#overflow-simple-addsol
 * Original pragma: 0.4.25
 * Original vulnerable line: 14  (balance += deposit;)
 * Report marker: <yes> <report> ARITHMETIC
 *
 * MIGRATION NOTES (0.4.25 -> 0.8.24):
 *   - pragma raised to ^0.8.24.
 *   - `uint` -> `uint256`, explicit `public` visibility added.
 *   - Dataset contract name `Overflow_Add` renamed to the required Pascal
 *     fixture name `OverflowSimpleAdd`.
 *   - SEMANTICS-PRESERVING EDIT (deliberate, NOT a fix): the original wrapping
 *     addition is restored inside an `unchecked { ... }` block because 0.8
 *     otherwise reverts on overflow and would mask the bug.
 *   - No functions were added or removed.
 */
pragma solidity ^0.8.24;

contract OverflowSimpleAdd {
    uint256 public balance = 1;

    function add(uint256 deposit) public {
        // <yes> <report> ARITHMETIC
        unchecked {
            balance += deposit;
        }
    }
}
