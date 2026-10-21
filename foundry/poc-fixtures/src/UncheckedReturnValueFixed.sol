// SPDX-License-Identifier: MIT
/*
 * FIXED VARIANT of dataset/unchecked_low_level_calls/unchecked_return_value.sol
 * (smartbugs/smartbugs-curated)
 *
 * Standard remediation: capture the low-level call's success flag and revert
 * when the call failed, so a failed callee invocation can no longer pass
 * silently.
 */
pragma solidity ^0.8.24;

contract UncheckedReturnValueFixed {

    function callchecked(address callee) public {
        (bool ok, ) = callee.call("");
        require(ok);
    }

    function callnotchecked(address callee) public {
        // <yes> <report> UNCHECKED_LL_CALLS
        (bool ok, ) = callee.call("");
        require(ok, "call failed");
    }
}
