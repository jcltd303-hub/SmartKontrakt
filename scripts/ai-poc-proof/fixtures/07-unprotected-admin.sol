// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 07 (unprotected privileged function).
/// VULNERABLE BY DESIGN: mint() is a privileged action with no access
/// check at all -- anyone can mint themselves any amount.
contract UnguardedToken {
    string public constant name = "Unguarded";
    string public constant symbol = "UNGD";
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        // BUG: no onlyOwner / role check.
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
