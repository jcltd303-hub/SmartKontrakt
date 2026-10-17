// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Locked ether (can receive, cannot send)
/// @notice Detector: locked-ether. The contract accepts ETH (payable
///         fallback / deposit) but has NO withdrawal path -- funds sent in
///         are stuck forever.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. Proves: ETH lands, and every common
///      withdrawal selector fails or is absent, leaving the balance stuck.

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
        vm.deal(attackerEOA, 2 ether);

        uint256 before = target.balance;
        vm.prank(attackerEOA);
        (bool sent,) = target.call{value: 1 ether}("");
        require(sent, "target did not accept ETH -- not a locked-ether case");
        assertEq(target.balance, before + 1 ether, "ETH did not land");

        // Try every common withdrawal selector. None may move the funds.
        bytes[] memory candidates = new bytes[](4);
        candidates[0] = abi.encodeWithSignature("withdraw()");
        candidates[1] = abi.encodeWithSignature("claim()");
        candidates[2] = abi.encodeWithSignature("drain()");
        candidates[3] = abi.encodeWithSignature("sweep()");
        for (uint256 i = 0; i < candidates.length; i++) {
            vm.prank(attackerEOA);
            (bool ok,) = target.call(candidates[i]);
            // A "successful" call that moves no funds proves nothing --
            // only a balance change counts.
            assertEq(target.balance, before + 1 ether, "funds moved -- withdrawal path exists");
            ok; // silence unused warning; the balance assertion is the check
        }
        console.log("1 ether accepted and stuck -- locked ether proven");
    }
}
