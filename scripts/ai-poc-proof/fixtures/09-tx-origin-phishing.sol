// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 09 (tx.origin phishing).
/// VULNERABLE BY DESIGN: withdraw() authenticates with tx.origin
/// instead of msg.sender, so a malicious contract the owner is tricked
/// into calling can drain the wallet while tx.origin is still the
/// owner.
contract TxOriginWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function withdraw() external {
        // BUG: tx.origin auth.
        require(tx.origin == owner, "not the owner (tx.origin)");
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    receive() external payable {}
}
