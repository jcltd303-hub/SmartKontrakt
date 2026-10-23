// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 33 (variable shadowing mismatch).
/// VULNERABLE BY DESIGN: two variables track "the owner". owner()
/// reads `owner`, but setOwner() writes the SHADOW variable
/// `shadowOwner` -- the setter succeeds, a slot moves, and the
/// visible owner never changes. Every privileged check keeps
/// consulting the stale value.
contract ShadowVault {
    address public owner; // slot 0 -- the one owner() and the checks read
    address public shadowOwner; // slot 1 -- the one the setter writes

    constructor() {
        owner = msg.sender;
        shadowOwner = msg.sender;
    }

    function setOwner(address newOwner) external {
        // BUG: writes the shadow, not the variable owner() reads.
        shadowOwner = newOwner;
    }

    function sweep() external {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    receive() external payable {}
}
