// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// QNT shape: a public batch executor with no access control.
contract QntishBatch {
    function batch(address[] calldata targets, bytes[] calldata data) external {
        for (uint256 i = 0; i < targets.length; ++i) {
            (bool ok, ) = targets[i].call(data[i]);
            require(ok, "batch failed");
        }
    }
}
