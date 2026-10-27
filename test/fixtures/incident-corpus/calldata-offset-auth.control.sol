// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract RouterishSafe {
    struct BaseData { address payer; uint256 amount; }
    function swap(bytes calldata data, uint256 deadline) external payable {
        require(block.timestamp <= deadline, "expired");
        BaseData memory d = abi.decode(data, (BaseData));
        require(d.payer == msg.sender, "not payer");
        _spend(d.payer, d.amount);
    }
    function _spend(address from, uint256 amount) internal {
        // spends from's approval
    }
}
