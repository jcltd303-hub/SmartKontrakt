// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 * =========================================================================
 * Dataset:          smartbugs/smartbugs-curated
 * Dataset path:     dataset/reentrancy/reentrancy_cross_function.sol
 * Upstream source:  https://consensys.github.io/smart-contract-best-practices/known_attacks/
 * Original author:  consensys
 * Original pragma:  pragma solidity ^0.4.24;
 * Original vulnerable line: 24
 * Dataset report marker: // <yes> <report> REENTRANCY
 * =========================================================================
 *
 * This is the VULNERABLE port (contract CrossFunctionVault, renamed from the
 * dataset's Reentrancy_cross_function).
 *
 * Porting edits (0.4.24 -> 0.8.24 migration ONLY):
 *   - call.value(x)("")  ->  call{value: x}("")  (with an explicit success flag)
 *   - uint               ->  uint256
 *   - explicit visibility added to state variables / functions
 *
 * THE VULNERABLE ORDERING IS PRESERVED VERBATIM: withdrawBalance() performs the
 * external call (line 24 upstream) BEFORE it zeroes userBalances[msg.sender].
 * That ordering is the bug: during the callback the caller still has its full
 * credit, so it can re-enter transfer() and move that credit elsewhere, letting
 * it keep both the ETH that was just paid out AND a fresh credit claim.
 *
 * The dataset contract exposes no payable/deposit entry point, so the TEST seeds
 * the private `userBalances` mapping with vm.store and funds the contract with
 * vm.deal (documented in test/CrossFunctionVault.t.sol).
 */
pragma solidity ^0.8.24;

contract CrossFunctionVault {
    // INSECURE
    mapping(address => uint256) private userBalances;

    function transfer(address to, uint256 amount) public {
        if (userBalances[msg.sender] >= amount) {
            userBalances[to] += amount;
            userBalances[msg.sender] -= amount;
        }
    }

    function withdrawBalance() public {
        uint256 amountToWithdraw = userBalances[msg.sender];
        // <yes> <report> REENTRANCY
        (bool success, ) = msg.sender.call{value: amountToWithdraw}(""); // At this point, the caller's code is executed, and can call transfer()
        require(success);
        userBalances[msg.sender] = 0;
    }
}
