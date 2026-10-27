// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
interface IPoolManager4 {
    function take(address, address, uint256) external;
    function settle() external payable returns (uint256);
}
contract GoldPesaishHookSafe {
    IPoolManager4 public poolManager;
    uint256 public outstandingDelta;
    function lockAcquired(bytes calldata data) external returns (bytes memory) {
        require(outstandingDelta == 0, "delta unsettled");
        poolManager.take(address(this), address(this), 1 ether);
        poolManager.settle();
        return data;
    }
}
