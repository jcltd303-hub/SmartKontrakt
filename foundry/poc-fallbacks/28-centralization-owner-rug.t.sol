// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Centralization: owner can rug (proven via prank)
/// @notice Detector: centralization. One privileged key can move the whole
///         balance / mint / pause. On a fork, pranking the owner proves
///         the CAPABILITY without needing the key: if the owner CAN do it,
///         the finding is real (trust assumption, not a bug to exploit).
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. This is a CAPABILITY proof, not an
///      unauthorized exploit -- it shows what the trusted key can do.
///
///      This harness does NOT guess a single entry point. It tries every
///      plausible owner-only entry point and accepts the first that produces
///      the class OBSERVABLE -- an owner-only action MOVES value or state
///      with no timelock. A call that merely RETURNS is never treated as a
///      reproduction.

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

    function _readOwner() internal view returns (bool found, address owner_) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("owner()"));
        if (ok && ret.length == 32) return (true, abi.decode(ret, (address)));
        return (false, address(0));
    }

    function _balanceOf(address who) internal view returns (bool found, uint256 bal) {
        (bool ok, bytes memory ret) =
            target.staticcall(abi.encodeWithSignature("balanceOf(address)", who));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        return (false, 0);
    }

    /// A generic state fingerprint: the target's balance, its first 8 storage
    /// slots, and (if present) the actor's token balance. Any value or state
    /// move an owner-only action causes changes this.
    function _fingerprint(address who) internal view returns (uint256) {
        bytes memory acc = abi.encode(target.balance);
        for (uint256 i = 0; i < 8; i++) {
            acc = abi.encodePacked(acc, vm.load(target, bytes32(i)));
        }
        (bool found, uint256 bal) = _balanceOf(who);
        acc = abi.encodePacked(acc, found ? bal : uint256(0));
        return uint256(keccak256(acc));
    }

    /// Try ONE candidate, pranked as the owner, and accept it only when the
    /// class OBSERVABLE changes -- never because the call returned.
    /// `attacker` here is the OWNER. `before` is a state fingerprint snapshot.
    function _attempt(address attacker, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        vm.prank(attacker);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        // OBSERVABLE (centralization): an owner-only action MOVED value or
        // state with no timelock. A call that merely returned is not the rug.
        if (ok && _fingerprint(attacker) != before) return label;
        return "";
    }

    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        used = _attempt(attacker, before, "withdraw()", abi.encodeWithSignature("withdraw()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "withdrawAll()", abi.encodeWithSignature("withdrawAll()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "sweep()", abi.encodeWithSignature("sweep()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "mint(address,uint256)",
            abi.encodeWithSignature("mint(address,uint256)", attacker, 1000 ether)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "setFee(uint256)",
            abi.encodeWithSignature("setFee(uint256)", uint256(10_000))
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "pause()", abi.encodeWithSignature("pause()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "burn(address)",
            abi.encodeWithSignature("burn(address)", attacker)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "upgradeTo(address)",
            abi.encodeWithSignature("upgradeTo(address)", attacker)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "upgradeToAndCall(address,bytes)",
            abi.encodeWithSignature("upgradeToAndCall(address,bytes)", attacker, bytes(""))
        );
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_exploit() public {
        (bool found, address owner_) = _readOwner();
        require(found, "target has no owner() view -- set the owner address manually");
        console.log("owner:", owner_);

        // OBSERVABLE snapshot: the target's state fingerprint.
        uint256 before = _fingerprint(owner_);

        string memory used = _tryEntry(owner_, before);

        assertTrue(
            bytes(used).length > 0,
            "not reproduced via any tried entry point. Candidates tried: withdraw(), withdrawAll(), sweep(), mint(address,uint256), setFee(uint256), pause(), burn(address), upgradeTo(address), upgradeToAndCall(address,bytes) -- each either RETURNED (a no-op) or left value/state unchanged. This does NOT establish safety: the privileged action may be under another name. Adapt the candidate list."
        );
        console.log("owner-only capability proven via", used, "-- no timelock");
    }
}
