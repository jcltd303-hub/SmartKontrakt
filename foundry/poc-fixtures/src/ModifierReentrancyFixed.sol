// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 * =========================================================================
 * Dataset:          smartbugs/smartbugs-curated
 * Dataset path:     dataset/reentrancy/modifier_reentrancy.sol
 * Upstream source:  https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/reentracy/modifier_reentrancy.sol
 * Original pragma:  pragma solidity ^0.4.24;
 * Original vulnerable line: 15
 * =========================================================================
 *
 * FIXED variant (contract ModifierReentrancyFixed).
 *
 * Remediation: a nonReentrant guard, applied OUTERMOST (before hasNoBalance and
 * supportsToken). It is set before the modifier's external call, so the
 * re-entrant airDrop() reverts on the guard. Modifier order still keeps the
 * hasNoBalance-before-supportsToken semantics of the original.
 */
pragma solidity ^0.8.24;

import {ModifierReentrancyBank} from "./ModifierReentrancy.sol";

contract ModifierReentrancyFixed {
    mapping(address => uint256) public tokenBalance;
    string constant name = "Nu Token";
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "reentrancy");
        locked = true;
        _;
        locked = false;
    }

    // If a contract has a zero balance and supports the token give them some token
    function airDrop() public nonReentrant hasNoBalance supportsToken {
        tokenBalance[msg.sender] += 20;
    }

    // Checks that the contract responds the way we want
    modifier supportsToken() {
        require(keccak256(abi.encodePacked("Nu Token")) == ModifierReentrancyBank(msg.sender).supportsToken());
        _;
    }

    // Checks that the caller has a zero balance
    modifier hasNoBalance {
        require(tokenBalance[msg.sender] == 0);
        _;
    }
}
