// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract FlashLoopishSafe {
    mapping(address => bool) public authorised;
    function pull(address token) external {
        require(authorised[msg.sender], "not authorised");
        (bool ok, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, 1 ether));
        require(ok, "transfer failed");
    }
}
