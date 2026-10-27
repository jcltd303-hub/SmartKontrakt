// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// Cork Protocol shape: a v4 hook callback with no PoolManager caller check.
interface IPoolManager {
    function take(address, address, uint256) external;
    function settle() external payable returns (uint256);
}
contract CorkishHook {
    IPoolManager public poolManager;
    address public token;
    uint256 public recordedPrice;
    function beforeSwap(address sender, bytes calldata key, bytes calldata params, bytes calldata hookData) external returns (bytes4) {
        // no caller check: anyone can drive settlement outside a real swap
        recordedPrice = abi.decode(hookData, (uint256));
        poolManager.take(token, address(this), 1 ether);
        poolManager.settle();
        return this.beforeSwap.selector;
    }
}
