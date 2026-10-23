// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 06 (open drain / unprotected ether).
/// VULNERABLE BY DESIGN: withdraw() has no access check and no
/// entitlement bound -- anyone can sweep the whole balance.
contract OpenDrainVault {
    function withdraw() external {
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    receive() external payable {}
}
