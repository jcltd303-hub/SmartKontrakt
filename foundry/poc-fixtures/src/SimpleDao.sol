// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SimpleDAO — modernized port of a SmartBugs Curated contract
///
/// PROVENANCE
///   Dataset  : smartbugs/smartbugs-curated @ 230e6491
///              dataset/reentrancy/simple_dao.sol
///   Upstream : http://blockchain.unica.it/projects/ethereum-survey/attacks.html#simpledao
///   Category : reentrancy (DASP / SmartBugs)
///   Original : pragma ^0.4.2, vulnerable at line 19
///
/// @dev The ONLY edits from the dataset contract are the 0.8 migration:
///   `msg.sender.call.value(amount)()` — removed in 0.8 — becomes
///   `(bool res, ) = msg.sender.call{value: amount}("")`, plus explicit
///   visibility and `view` on the query. The vulnerable ordering is preserved
///   VERBATIM: the credit is debited AFTER the external call, so a re-entrant
///   withdraw sees the un-debited credit. That ordering is the bug.
///
///   One further edit, deliberate and non-fixing: the debit is wrapped in
///   `unchecked { }`. A profitable re-entrant drain necessarily debits more than
///   the credit holds, which 0.4 wrapped silently and 0.8 would revert — that
///   would mask the bug rather than migrate it.
contract SimpleDao {
    mapping(address => uint256) public credit;

    function donate(address to) public payable {
        credit[to] += msg.value;
    }

    function withdraw(uint256 amount) public {
        if (credit[msg.sender] >= amount) {
            // <yes> <report> REENTRANCY   (original line 19)
            (bool res, ) = msg.sender.call{value: amount}("");
            // 0.4.x wrapped silently; 0.8 would revert and mask the exploit.
            // `unchecked` preserves the original arithmetic semantics.
            unchecked {
                credit[msg.sender] -= amount;
            }
        }
    }

    function queryCredit(address to) public view returns (uint256) {
        return credit[to];
    }
}
