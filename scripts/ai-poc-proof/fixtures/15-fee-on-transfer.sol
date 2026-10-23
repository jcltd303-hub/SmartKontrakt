// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IFotToken {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// Fixture for fallback type 15 (fee-on-transfer accounting mismatch).
/// VULNERABLE BY DESIGN: deposit() credits the FULL requested amount
/// while a fee-on-transfer token delivers less, so the ledger exceeds
/// the vault's real token balance from the first deposit.
contract FotVault {
    IFotToken public token;
    mapping(address => uint256) public credits;

    function setToken(address token_) external {
        token = IFotToken(token_);
    }

    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "pull failed");
        // BUG: credits `amount`, not the balance delta actually received.
        credits[msg.sender] += amount;
    }
}
