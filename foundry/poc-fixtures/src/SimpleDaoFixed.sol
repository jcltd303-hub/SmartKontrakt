// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SimpleDAO (fixed) — the same contract with the bug removed.
/// @dev Two standard remediations: checks-effects-interactions (debit before the
///      external call) and a reentrancy guard. Exists so the fixture harness can
///      be checked for discrimination: a harness that fires on this contract is
///      a false positive.
contract SimpleDaoFixed {
    mapping(address => uint256) public credit;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function donate(address to) public payable {
        credit[to] += msg.value;
    }

    function withdraw(uint256 amount) public nonReentrant {
        if (credit[msg.sender] >= amount) {
            // Effects BEFORE the interaction.
            credit[msg.sender] -= amount;
            (bool res, ) = msg.sender.call{value: amount}("");
            require(res, "send failed");
        }
    }

    function queryCredit(address to) public view returns (uint256) {
        return credit[to];
    }
}
