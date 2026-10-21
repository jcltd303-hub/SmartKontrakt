// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 * Dataset: smartbugs/smartbugs-curated
 * Dataset path: dataset/arithmetic/integer_overflow_mul.sol
 * @source: https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/integer_overflow_and_underflow/integer_overflow_mul.sol
 * Original pragma: ^0.4.19
 * Original vulnerable line: 17  (count *= input;)
 * Report marker: <yes> <report> ARITHMETIC
 *
 * MIGRATION NOTES (0.4.19 -> 0.8.24):
 *   - pragma raised to ^0.8.24.
 *   - `uint` -> `uint256`, explicit `public` visibility added.
 *   - SEMANTICS-PRESERVING EDIT (deliberate, NOT a fix): the original wrapping
 *     multiplication is restored inside an `unchecked { ... }` block because
 *     0.8 otherwise reverts on overflow and would mask the bug.
 *   - No functions were added or removed.
 */
pragma solidity ^0.8.24;

//Single transaction overflow
//Post-transaction effect: overflow escapes to publicly-readable storage

contract IntegerOverflowMul {
    uint256 public count = 2;

    function run(uint256 input) public {
        // <yes> <report> ARITHMETIC
        unchecked {
            count *= input;
        }
    }
}
