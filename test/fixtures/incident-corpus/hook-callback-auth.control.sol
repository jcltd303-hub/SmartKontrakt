// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
interface IPoolManager2 {
    function take(address, address, uint256) external;
    function settle() external payable returns (uint256);
}
contract CorkishHookSafe {
    IPoolManager2 public poolManager;
    address public token;
    uint256 public recordedPrice;
    modifier onlyPoolManager() {
        require(msg.sender == address(poolManager), "not pool manager");
        _;
    }
    function beforeSwap(address sender, bytes calldata key, bytes calldata params, bytes calldata hookData) external onlyPoolManager returns (bytes4) {
        recordedPrice = abi.decode(hookData, (uint256));
        poolManager.take(token, address(this), 1 ether);
        poolManager.settle();
        return this.beforeSwap.selector;
    }
}
