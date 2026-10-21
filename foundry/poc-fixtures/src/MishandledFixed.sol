// SPDX-License-Identifier: MIT
/*
 * FIXED VARIANT of dataset/unchecked_low_level_calls/mishandled.sol
 * (smartbugs/smartbugs-curated)
 *
 * Standard remediation: check the return value of the low-level send and revert
 * when it fails, so a failed transfer can no longer silently zero the caller's
 * recorded balance. (Either the funds are delivered, or the whole withdrawal
 * reverts and the bookkeeping is rolled back.)
 */
pragma solidity ^0.8.24;

contract MishandledFixed {
    mapping(address => uint256) userBalances;

    function withdrawBalance() public {
        uint256 amountToWithdraw = userBalances[msg.sender];
        userBalances[msg.sender] = 0;
        // <yes> <report> UNCHECKED_LL_CALLS
        require(payable(msg.sender).send(amountToWithdraw), "send failed");
    }
}
