// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ReentrancyDAO (fixed) — the same contract with the bug removed.
///
/// This exists so the fixture harness can be checked for DISCRIMINATION, not
/// just for firing: an exploit harness that "passes" against a fixed contract
/// is a false positive. Two changes, both standard remediations:
///   1. checks-effects-interactions — zero the credit BEFORE the external call;
///   2. a reentrancy guard on the entry point.
contract ReentrancyDaoFixed {
    mapping(address => uint256) public credit;
    uint256 public balance;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() public payable {
        credit[msg.sender] += msg.value;
        balance += msg.value;
    }

    function withdrawAll() public nonReentrant {
        uint256 oCredit = credit[msg.sender];
        if (oCredit > 0) {
            // Effects BEFORE the interaction.
            credit[msg.sender] = 0;
            balance -= oCredit;
            (bool callResult, ) = msg.sender.call{value: oCredit}("");
            require(callResult);
        }
    }
}
