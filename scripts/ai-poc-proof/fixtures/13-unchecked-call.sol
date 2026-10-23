// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 13 (unchecked low-level call).
/// VULNERABLE BY DESIGN: execute() forwards to a caller-chosen callee
/// and records success WITHOUT checking the call result -- a
/// reverting callee still leaves the operation marked executed.
contract UncheckedForwarder {
    uint256 public executedCount;
    bool public lastMarkedSuccess;

    function execute(address to, bytes calldata data) external {
        // BUG: return value ignored.
        (bool ok, ) = to.call(data);
        ok;
        executedCount += 1;
        lastMarkedSuccess = true;
    }
}
