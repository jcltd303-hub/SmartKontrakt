// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 * Dataset: smartbugs/smartbugs-curated
 * Dataset path: dataset/arithmetic/integer_overflow_add.sol
 * @source: https://github.com/ConsenSys/evm-analyzer-benchmark-suite/blob/master/benchmarks/integer_overflow_add.sol
 * Original pragma: ^0.4.19
 * Original vulnerable line: 17  (count += input;)
 * Report marker: <yes> <report> ARITHMETIC
 *
 * MIGRATION NOTES (0.4.19 -> 0.8.24):
 *   - pragma raised to ^0.8.24.
 *   - `uint` -> `uint256`, explicit `public` visibility added.
 *   - SEMANTICS-PRESERVING EDIT (deliberate, NOT a fix): Solidity 0.8 reverts on
 *     arithmetic overflow/underflow by default, which would silently destroy this
 *     vulnerability. The original wrapping behaviour is restored by placing the
 *     exact original statement `count += input;` inside an `unchecked { ... }`
 *     block. The vulnerable statement, its ordering, and its operands are
 *     otherwise byte-for-byte identical to the dataset contract.
 *   - No functions were added or removed.
 */
pragma solidity ^0.8.24;

//Single transaction overflow
//Post-transaction effect: overflow escapes to publicly-readable storage

contract IntegerOverflowAdd {
    uint256 public count = 1;

    function run(uint256 input) public {
        // <yes> <report> ARITHMETIC
        unchecked {
            count += input;
        }
    }
}
