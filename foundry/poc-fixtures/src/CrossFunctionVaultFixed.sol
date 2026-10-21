// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 * =========================================================================
 * Dataset:          smartbugs/smartbugs-curated
 * Dataset path:     dataset/reentrancy/reentrancy_cross_function.sol
 * Upstream source:  https://consensys.github.io/smart-contract-best-practices/known_attacks/
 * Original pragma:  pragma solidity ^0.4.24;
 * Original vulnerable line: 24
 * =========================================================================
 *
 * FIXED variant (contract CrossFunctionVaultFixed).
 *
 * Remediation: checks-effects-interactions. The balance is zeroed BEFORE the
 * external call, so a re-entrant transfer() observes userBalances[msg.sender]
 * == 0 and its `>= amount` guard fails -> the credit-move is a no-op. The ETH
 * is still paid out (the legitimate withdrawal succeeds); only the duplication
 * is prevented.
 */
pragma solidity ^0.8.24;

contract CrossFunctionVaultFixed {
    mapping(address => uint256) private userBalances;

    function transfer(address to, uint256 amount) public {
        if (userBalances[msg.sender] >= amount) {
            userBalances[to] += amount;
            userBalances[msg.sender] -= amount;
        }
    }

    function withdrawBalance() public {
        uint256 amountToWithdraw = userBalances[msg.sender];
        userBalances[msg.sender] = 0; // EFFECT before INTERACTION (fix)
        (bool success, ) = msg.sender.call{value: amountToWithdraw}("");
        require(success);
    }
}
