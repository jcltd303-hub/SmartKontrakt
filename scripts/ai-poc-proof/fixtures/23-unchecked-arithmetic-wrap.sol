// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 23 (unchecked arithmetic wrap).
/// VULNERABLE BY DESIGN: burn() subtracts inside an unchecked{}
/// block, so burning more than the balance WRAPS it instead of
/// reverting.
contract WrapToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor() {
        balanceOf[msg.sender] = 1000;
        totalSupply = 1000;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        unchecked {
            balanceOf[msg.sender] -= amount;
        }
        balanceOf[to] += amount; // checked: the wrapped self-transfer reverts here
        return true;
    }

    function burn(uint256 amount) external {
        // BUG: unchecked subtraction wraps a zero balance to 2^256 - amount.
        unchecked {
            balanceOf[msg.sender] -= amount;
            totalSupply -= amount;
        }
    }
}
