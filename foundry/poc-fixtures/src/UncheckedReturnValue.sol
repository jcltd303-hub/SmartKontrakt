// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 * Dataset: smartbugs/smartbugs-curated
 * Dataset path: dataset/unchecked_low_level_calls/unchecked_return_value.sol
 * @source: https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-104#unchecked-return-valuesol
 * Original pragma: 0.4.25
 * Original vulnerable line: 17  (callee.call();)
 * Report marker: <yes> <report> UNCHECKED_LL_CALLS
 *
 * MIGRATION NOTES (0.4.25 -> 0.8.24):
 *   - pragma raised to ^0.8.24.
 *   - `callee.call()` -> `callee.call("")` (0.5+ low-level call syntax). The
 *     call's (bool, bytes) return is deliberately discarded in
 *     `callnotchecked`, preserving the unchecked-return-value bug. The checked
 *     sibling `callchecked` is migrated to `(bool ok,) = callee.call(""); require(ok);`.
 *   - Dataset contract name `ReturnValue` renamed to the required Pascal fixture
 *     name `UncheckedReturnValue`.
 *   - No functions were added or removed.
 */
pragma solidity ^0.8.24;

contract UncheckedReturnValue {

    function callchecked(address callee) public {
        (bool ok, ) = callee.call("");
        require(ok);
    }

    function callnotchecked(address callee) public {
        // <yes> <report> UNCHECKED_LL_CALLS
        (bool success, ) = callee.call("");
        success;
    }
}
