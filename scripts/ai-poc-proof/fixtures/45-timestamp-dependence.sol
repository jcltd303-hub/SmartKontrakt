// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for 45-timestamp-dependence (detectors: timestamp,
/// bytecode-timestamp). The sale state -- and the claim it gates -- is
/// decided by block.timestamp alone, a value the block producer can
/// steer within consensus drift.
contract TimestampSale {
    uint256 public endTime;
    bool public claimed;

    constructor(uint256 endTime_) {
        endTime = endTime_;
    }

    receive() external payable {}

    /// VULNERABLE: time gate reads block.timestamp directly.
    function isSaleFinished() public view returns (bool) {
        return block.timestamp >= endTime;
    }

    function claim() public {
        require(isSaleFinished(), "sale not finished");
        require(!claimed, "already claimed");
        claimed = true;
        (bool ok,) = payable(msg.sender).call{value: address(this).balance}("");
        require(ok);
    }
}
