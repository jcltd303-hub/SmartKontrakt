// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 39 (DoS: revert-in-loop + unbounded loop).
/// VULNERABLE BY DESIGN, twice over:
///  (a) distribute() push-pays every recipient in a loop and reverts
///      the WHOLE distribution when one recipient reverts.
///  (b) process() iterates an array anyone can grow via push(), so
///      its gas cost grows without bound.
contract DosDistributor {
    address[] public recipients;
    uint256[] public items;
    uint256 public processedTotal;

    function addRecipient(address who) external {
        // Unguarded on purpose -- anyone can register a recipient.
        recipients.push(who);
    }

    function distribute() external {
        for (uint256 i = 0; i < recipients.length; i++) {
            // BUG (a): one reverting recipient bricks everyone's payout.
            (bool ok, ) = payable(recipients[i]).call{value: 0.1 ether}("");
            require(ok, "a recipient reverted -- distribution bricked");
        }
    }

    function push(uint256 v) external {
        items.push(v);
    }

    function process() external {
        uint256 sum = processedTotal;
        for (uint256 i = 0; i < items.length; i++) {
            sum += items[i];
        }
        processedTotal = sum;
    }

    receive() external payable {}
}
