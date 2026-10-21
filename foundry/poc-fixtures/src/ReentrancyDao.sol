// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ReentrancyDAO — modernized port of a SmartBugs Curated contract
///
/// PROVENANCE
///   Dataset  : smartbugs/smartbugs-curated @ 230e6491
///              dataset/reentrancy/reentrancy_dao.sol
///   Upstream : https://github.com/ConsenSys/evm-analyzer-benchmark-suite
///   Category : reentrancy (DASP / SmartBugs)
///   Original : pragma ^0.4.19, vulnerable at line 18
///
/// @dev The ONLY edits from the dataset contract are the 0.8 migration:
///   `msg.sender.call.value(x)()` — removed in Solidity 0.8 — becomes
///   `msg.sender.call{value: x}("")`, plus explicit visibility on the view.
///   The vulnerable ordering is preserved VERBATIM: the credit is zeroed AFTER
///   the external call, and there is no reentrancy guard. That is what makes
///   this a valid reproduction target for the reentrancy harness.
contract ReentrancyDao {
    mapping(address => uint256) public credit;
    uint256 public balance;

    function deposit() public payable {
        credit[msg.sender] += msg.value;
        balance += msg.value;
    }

    function withdrawAll() public {
        uint256 oCredit = credit[msg.sender];
        if (oCredit > 0) {
            balance -= oCredit;
            // <yes> <report> REENTRANCY   (original line 18)
            (bool callResult, ) = msg.sender.call{value: oCredit}("");
            require(callResult);
            credit[msg.sender] = 0;
        }
    }
}
