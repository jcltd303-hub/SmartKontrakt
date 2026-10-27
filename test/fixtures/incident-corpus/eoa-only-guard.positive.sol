// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// POT token shape: tx.origin == msg.sender used as the flash-loan guard.
interface IRouter { function swapExactTokensForTokens(uint256, uint256, address[] calldata, address, uint256) external returns (uint256[] memory); }
contract Potish {
    IRouter public router;
    function buy(uint256 amountIn) external {
        require(tx.origin == msg.sender, "no contracts");
        address[] memory path = new address[](2);
        path[0] = address(this);
        path[1] = address(0);
        router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, block.timestamp);
    }
}
