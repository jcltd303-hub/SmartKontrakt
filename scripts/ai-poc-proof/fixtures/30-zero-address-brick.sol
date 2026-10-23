// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 30 (zero-address write bricks the
/// contract). VULNERABLE BY DESIGN: setOwner() lacks a zero-address
/// check, so the owner can be set to address(0) -- after which every
/// onlyOwner action reverts for everyone, forever.
contract ZeroBrick {
    address public owner; // slot 0

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setOwner(address newOwner) external onlyOwner {
        // BUG: no newOwner != address(0) check.
        owner = newOwner;
    }

    function withdraw() external onlyOwner {
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    receive() external payable {}
}
