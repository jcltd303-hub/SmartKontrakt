// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 01 (classic reentrancy).
/// VULNERABLE BY DESIGN: withdraw() sends ETH before zeroing the caller's
/// balance, so a contract caller re-enters and drains more than it deposited.
contract ReentrancyVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        // BUG: state update after the external call.
        balances[msg.sender] = 0;
    }

    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }

    receive() external payable {}
}
