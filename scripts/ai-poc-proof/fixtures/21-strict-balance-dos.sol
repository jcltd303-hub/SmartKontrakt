// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 21 (strict balance equality DoS).
/// VULNERABLE BY DESIGN: withdraw() requires the contract balance to
/// be EXACTLY the expected pot. One forced wei (selfdestruct) breaks
/// the equality forever and the pot is bricked. The suite setup funds
/// the fixture with exactly EXPECTED.
contract StrictBalanceVault {
    uint256 public constant EXPECTED = 5 ether;

    function withdraw() external {
        // BUG: exact-equality gate on a publicly force-feedable balance.
        require(address(this).balance == EXPECTED, "balance must be exact");
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "payout failed");
    }

    receive() external payable {}
}
