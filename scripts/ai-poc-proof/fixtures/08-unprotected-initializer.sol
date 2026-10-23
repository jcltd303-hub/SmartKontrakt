// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 08 (unprotected initializer).
/// VULNERABLE BY DESIGN: initialize() has no initializer guard and no
/// access check -- anyone can call it at any time and become owner.
contract UnguardedInitializer {
    address public owner; // slot 0
    bool public initialized;

    function initialize(address newOwner) external {
        // BUG: callable by anyone, any number of times.
        owner = newOwner;
        initialized = true;
    }

    function sweep() external {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    receive() external payable {}
}
