// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 37 (approval abuse).
/// A plain ERC-20 with the standard approve/transferFrom semantics the
/// class is about: a standing max approval lets the spender drain the
/// victim at will, and a non-zero -> non-zero approve change can be
/// raced (spend the old, then spend the new). The suite setup mints to
/// the VICTIM account and records VICTIM -> SPENDER approval on-chain.
contract RaceToken {
    string public constant name = "RaceToken";
    string public constant symbol = "RACE";
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "allowance");
        require(balanceOf[from] >= amount, "insufficient");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
