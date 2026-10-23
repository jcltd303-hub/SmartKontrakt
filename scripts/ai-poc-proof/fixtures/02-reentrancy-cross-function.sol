// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 02 (cross-function reentrancy).
/// Two functions share ONE balance ledger. withdraw() pays out against
/// the ledger and only zeroes it AFTER the external call; transfer()
/// pays out against the SAME not-yet-updated ledger during the callback
/// and never debits it. The credit is therefore spent twice: once as
/// ETH via the callback's transfer(), once again via the second
/// withdraw() in the template's attack().
contract CrossFunctionVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        // BUG: ledger updated after the external call -- and a second
        // withdraw() against an already-settled (zero) ledger is a
        // harmless no-op here, which is what lets the template's
        // attack() sequence run: the damage was done inside the
        // callback window, by transfer().
        balances[msg.sender] = 0;
    }

    /// Second function reading the same ledger mid-settlement. It pays
    /// out against the caller's credit but forgets to debit that credit.
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient credit");
        (bool ok, ) = payable(to).call{value: amount}("");
        require(ok, "payout failed");
        // BUG: credit spent here is never debited.
    }

    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }

    receive() external payable {}
}
