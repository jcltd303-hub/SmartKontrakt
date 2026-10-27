// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// FlashLoopAdapter shape: the guard asks the CALLER whether it is authorised.
interface IModuleGuard { function isModuleEnabled(address) external view returns (bool); }
contract FlashLoopish {
    address public sink;
    function pull(address token) external {
        require(IModuleGuard(msg.sender).isModuleEnabled(address(this)), "not enabled");
        (bool ok, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, 1 ether));
        require(ok, "transfer failed");
    }
}
