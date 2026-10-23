// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IBoolToken {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// Fixture for fallback type 14 (unchecked ERC-20 bool).
/// VULNERABLE BY DESIGN: claim() credits the caller's ledger and calls
/// token.transfer() while ignoring the returned bool -- a token that
/// returns false (USDT-style failure) still leaves the credit in place.
contract FalseBoolVault {
    IBoolToken public token;
    mapping(address => uint256) public credits;

    function setToken(address token_) external {
        // Unguarded setter as well: the point of the fixture is claim().
        token = IBoolToken(token_);
    }

    function claim(uint256 amount) external {
        credits[msg.sender] += amount;
        // BUG: false return ignored -- the credit above stands either way.
        token.transfer(msg.sender, amount);
    }
}
