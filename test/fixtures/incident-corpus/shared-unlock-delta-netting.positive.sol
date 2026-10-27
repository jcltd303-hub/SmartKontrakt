// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// GoldPesa shape: take and settle inside the caller's unlock, no delta check.
interface IPoolManager3 {
    function take(address, address, uint256) external;
    function settle() external payable returns (uint256);
}
contract GoldPesaishHook {
    IPoolManager3 public poolManager;
    function lockAcquired(bytes calldata data) external returns (bytes memory) {
        poolManager.take(address(this), address(this), 1 ether);
        poolManager.settle();
        return data;
    }
}
