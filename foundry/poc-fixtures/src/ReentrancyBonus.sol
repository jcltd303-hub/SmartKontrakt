// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 * =========================================================================
 * Dataset:          smartbugs/smartbugs-curated
 * Dataset path:     dataset/reentrancy/reentrancy_bonus.sol
 * Upstream source:  https://consensys.github.io/smart-contract-best-practices/known_attacks/
 * Original author:  consensys
 * Original pragma:  pragma solidity ^0.4.24;
 * Original vulnerable line: 28
 * Dataset report marker: // <yes> <report> REENTRANCY
 * =========================================================================
 *
 * This is the VULNERABLE port (contract ReentrancyBonus, renamed from the
 * dataset's Reentrancy_bonus).
 *
 * Porting edits (0.4.24 -> 0.8.24 migration ONLY):
 *   - call.value(x)("")  ->  call{value: x}("")  (with an explicit success flag)
 *   - uint               ->  uint256
 *   - explicit visibility
 *
 * THE VULNERABLE ORDERING IS PRESERVED VERBATIM: getFirstWithdrawalBonus() sets
 * `claimedBonus[recipient] = true` only AFTER withdrawReward() has already made
 * its external call (line 28 upstream). The re-entrant call therefore still sees
 * claimedBonus == false and can claim the bonus again, draining the contract.
 *
 * The dataset contract exposes no payable/deposit entry point, so the TEST funds
 * it with vm.deal (documented in test/ReentrancyBonus.t.sol).
 */
pragma solidity ^0.8.24;

contract ReentrancyBonus {
    // INSECURE
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
        require(!claimedBonus[recipient]); // Each recipient should only be able to claim the bonus once

        rewardsForA[recipient] += 100;
        // <yes> <report> REENTRANCY
        withdrawReward(recipient); // At this point, the caller will be able to execute getFirstWithdrawalBonus again.
        claimedBonus[recipient] = true;
    }
}
