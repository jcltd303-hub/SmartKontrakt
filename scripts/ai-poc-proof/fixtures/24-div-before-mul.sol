// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 24 (division before multiplication).
/// VULNERABLE BY DESIGN: calculate() divides first, so any amount
/// smaller than the total truncates to zero before the multiply can
/// scale it back up.
contract DivFirstCalc {
    function total() external pure returns (uint256) {
        return 3;
    }

    function share() external pure returns (uint256) {
        return 10;
    }

    function calculate(uint256 amount) external pure returns (uint256) {
        // BUG: amount / total * share -- (1 / 3) * 10 == 0.
        return (amount / 3) * 10;
    }
}
