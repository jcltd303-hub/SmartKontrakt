// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 28 (centralization / owner rug
/// capability). One key controls everything: the owner can sweep the
/// entire balance instantly, with no timelock or multisig. The
/// template proves the CAPABILITY by pranking the owner.
contract OwnerRugVault {
    address public owner; // slot 0

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function withdraw() external onlyOwner {
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    receive() external payable {}
}
