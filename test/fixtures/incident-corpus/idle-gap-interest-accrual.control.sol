// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract BiFiishMarketSafe {
    uint256 public lastBlock;
    uint256 public interestIndex;
    uint256 public rate;
    function accrue() external {
        uint256 elapsed = block.number - lastBlock;
        lastBlock = block.number;
        interestIndex += elapsed * rate;
    }
}
