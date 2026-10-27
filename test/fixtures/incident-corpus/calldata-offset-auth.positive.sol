// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// UniswapV4Router04 shape: the payer is read at a fixed calldata offset.
contract Routerish {
    function swap(bytes calldata data, uint256 deadline) external payable {
        require(block.timestamp <= deadline, "expired");
        address payer;
        assembly {
            payer := calldataload(164)
            if iszero(eq(payer, caller())) { revert(0, 0) }
        }
        _spend(payer, data);
    }
    function _spend(address from, bytes calldata data) internal {
        uint256 amount = abi.decode(data, (uint256));
        // spends from's approval
    }
}
