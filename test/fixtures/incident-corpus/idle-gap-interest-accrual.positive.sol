// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// BiFi shape: the checkpoint advances only on one path, so the gap re-charges.
contract BiFiishMarket {
    uint256 public lastBlock;
    uint256 public interestIndex;
    uint256 public rate;
    function accrue() external {
        uint256 elapsed = block.number - lastBlock;
        interestIndex += elapsed * rate;
        if (interestIndex == 0) { lastBlock = block.number; }
    }
}
