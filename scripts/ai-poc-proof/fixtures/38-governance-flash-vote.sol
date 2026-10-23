// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 38 (governance flash vote).
/// VULNERABLE BY DESIGN: the contract is both the governance token and
/// the governor, and vote() weighs the caller's CURRENT balance -- no
/// snapshot, no checkpoint. Tokens held for one transaction (the
/// template borrows them from a whale and repays in the same test)
/// count at full weight.
contract GovToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(uint256 => uint256) public proposalForVotes;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
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

    function vote(uint256 proposalId, bool support) external {
        // BUG: spot balance as voting weight -- flash-borrowable.
        uint256 weight = balanceOf[msg.sender];
        require(weight > 0, "no voting power");
        if (support) {
            proposalForVotes[proposalId] += weight;
        }
    }
}
