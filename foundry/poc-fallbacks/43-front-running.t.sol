// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Front-running (Transaction Ordering)
/// @notice Detector: front-running. A function (e.g., withdraw, claim) is
///         unprotected and can be front-run by a higher gas-fee transaction
///         to steal the intended reward or action.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh.

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

    function test_exploit() public {
        // TODO: Replace this guard only after implementing target-specific
        // calldata and an observable before/after exploit-effect assertion.
        // A successful low-level call alone is not evidence of a vulnerability.
        revert("TEMPLATE_NOT_ADAPTED: target-specific exploit assertion required");
        address victim = makeAddr("victim");
        address attacker = makeAddr("attacker");
        
        // Setup: Victim is about to perform an action (e.g., withdraw)
        // Attacker observes mempool and sends a higher-gas transaction
        
        vm.prank(attacker);
        // TODO: Adapt to the target's vulnerable function
        (bool ok,) = target.call(abi.encodeWithSignature("claimReward()"));
        
        assertTrue(ok, "Front-running exploit failed");
        console.log("Attacker successfully claimed reward before victim");
    }
}
