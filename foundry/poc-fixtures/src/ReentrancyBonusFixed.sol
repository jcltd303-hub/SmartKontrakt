// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 * =========================================================================
 * Dataset:          smartbugs/smartbugs-curated
 * Dataset path:     dataset/reentrancy/reentrancy_bonus.sol
 * Upstream source:  https://consensys.github.io/smart-contract-best-practices/known_attacks/
 * Original pragma:  pragma solidity ^0.4.24;
 * Original vulnerable line: 28
 * =========================================================================
 *
 * FIXED variant (contract ReentrancyBonusFixed).
 *
 * Remediation: checks-effects-interactions. `claimedBonus[recipient] = true` is
 * set BEFORE withdrawReward() makes its external call, so a re-entrant
 * getFirstWithdrawalBonus() fails its `require(!claimedBonus[recipient])` guard
 * and the bonus can be claimed only once. (withdrawReward already zeroes the
 * reward before paying, so it needs no change.)
 */
pragma solidity ^0.8.24;

contract ReentrancyBonusFixed {
    mapping(address => uint256) private userBalances;
    mapping(address => bool) private claimedBonus;
    mapping(address => uint256) private rewardsForA;

    function withdrawReward(address recipient) public {
        uint256 amountToWithdraw = rewardsForA[recipient];
        rewardsForA[recipient] = 0;
        (bool success, ) = recipient.call{value: amountToWithdraw}("");
        require(success);
    }

    function getFirstWithdrawalBonus(address recipient) public {
        require(!claimedBonus[recipient]);

        claimedBonus[recipient] = true; // EFFECT before INTERACTION (fix)
        rewardsForA[recipient] += 100;
        withdrawReward(recipient);
    }
}
