// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// AlpsCon shape: the canonical Hardhat account sits on the verified whitelist.
contract AlpsConish {
    address public constant VERIFIED = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    mapping(address => bool) public onlyVerified;
    constructor() {
        onlyVerified[VERIFIED] = true;
    }
    function claimReward() external {
        require(onlyVerified[msg.sender], "not verified");
        payable(msg.sender).transfer(address(this).balance);
    }
}
