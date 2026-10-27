// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract QntishBatchSafe {
    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }
    function batch(address[] calldata targets, bytes[] calldata data) external onlyOwner {
        for (uint256 i = 0; i < targets.length; ++i) {
            (bool ok, ) = targets[i].call(data[i]);
            require(ok, "batch failed");
        }
    }
}
