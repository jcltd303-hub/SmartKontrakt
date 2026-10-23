// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 12 (selfdestruct sweep + forced ETH).
/// VULNERABLE BY DESIGN: kill() is unguarded -- anyone can destroy the
/// contract and sweep its balance to themselves. (Post-Cancun the code
/// survives a later-tx selfdestruct, but the balance still moves,
/// which is the observable the template asserts.)
contract KillableVault {
    function kill() external {
        // BUG: no access check on a destructive, balance-sweeping action.
        selfdestruct(payable(msg.sender));
    }

    receive() external payable {}
}
