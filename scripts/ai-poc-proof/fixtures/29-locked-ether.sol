// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 29 (locked ether).
/// VULNERABLE BY DESIGN: the contract happily ACCEPTS ether and has
/// no exit path at all -- no withdraw, claim, refund, or destroy.
/// Anything sent in is stuck forever. (Deliberately exposes no
/// candidate exit names; the template's inverted assertion is the
/// proof.)
contract LockedEther {
    uint256 public totalAccepted;

    receive() external payable {
        totalAccepted += msg.value;
    }
}
