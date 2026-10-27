// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract AlpsConishSafe {
    address public constant VERIFIED = 0x1111111111111111111111111111111111111111;
    mapping(address => bool) public onlyVerified;
    constructor() {
        onlyVerified[VERIFIED] = true;
    }
    function claimReward() external {
        require(onlyVerified[msg.sender], "not verified");
        payable(msg.sender).transfer(address(this).balance);
    }
}
