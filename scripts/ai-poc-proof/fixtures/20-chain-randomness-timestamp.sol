// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 20 (weak randomness + timestamp
/// dependence). VULNERABLE BY DESIGN, twice over:
///  - withdraw() is gated only on block.timestamp reaching
///    unlockTime -- time is validator-influenced and publicly known.
///  - guess() draws its "random" answer from block.timestamp --
///    anyone can compute it before calling.
contract TimeGame {
    uint256 public unlockTime;
    uint256 public lastPayout;

    constructor() {
        unlockTime = block.timestamp + 1 days;
    }

    function withdraw() external {
        require(block.timestamp >= unlockTime, "still locked");
        (bool ok, ) = msg.sender.call{value: 1 ether}("");
        require(ok, "payout failed");
        lastPayout = block.timestamp;
    }

    function guess(uint8 g) external {
        // BUG: the winning number is a public function of the block.
        require(g == uint8(block.timestamp % 256), "wrong guess");
        (bool ok, ) = msg.sender.call{value: 1 ether}("");
        require(ok, "payout failed");
        lastPayout = block.timestamp;
    }

    receive() external payable {}
}
