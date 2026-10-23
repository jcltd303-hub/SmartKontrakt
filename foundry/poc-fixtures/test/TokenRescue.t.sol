// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {TokenRescue} from "../src/TokenRescue.sol";
import {TokenRescueFixed} from "../src/TokenRescueFixed.sol";

/*
 * TokenRescue differential fixture test (modelled port — template
 * foundry/poc-fallbacks/46-token-rescue.t.sol; see src/TokenRescue.sol
 * for the provenance note).
 *
 * Setup (both halves): the token contract holds 500,000 of its OWN
 * token (the FUUU pattern: the contract was its own largest holder)
 * and 10 ether. An arbitrary attacker account — not the owner, not
 * the fixed wallet — calls the rescue functions.
 *
 * Vulnerable half: both calls SUCCEED from the attacker's account and
 * the contract is drained to the fixed DEV_WALLET. The attacker gains
 * nothing directly (the recipient is fixed) — what reproduces is the
 * missing access check itself: anyone can force the drain.
 *
 * Fixed half: the same calls REVERT from the attacker's account, the
 * balances are untouched, and the owner can still rescue (the fix is
 * the gate, not the removal of the function).
 */

contract TokenRescueFixtureTest is Test {
    address internal constant ATTACKER = address(0xA77AC6);
    uint256 internal constant SUPPLY = 1_000_000e18;
    uint256 internal constant HELD = 500_000e18;

    function test_fixtureReproduces() public {
        TokenRescue token = new TokenRescue(SUPPLY);
        address wallet = token.DEV_WALLET();

        // The contract holds its own token + ETH (the wild pattern).
        token.transfer(address(token), HELD);
        vm.deal(address(token), 10 ether);
        assertEq(token.balanceOf(address(token)), HELD, "setup: contract holds its own token");
        assertEq(address(token).balance, 10 ether, "setup: contract holds ETH");

        // An arbitrary account forces the own-token drain.
        vm.prank(ATTACKER);
        token.rescueERC20(address(token), HELD);
        assertEq(token.balanceOf(address(token)), 0, "REPRODUCED: own-token balance drained by a stranger");
        assertEq(token.balanceOf(wallet), HELD, "REPRODUCED: fixed wallet received the tokens");

        // And the ETH drain, same stranger, same missing check.
        vm.prank(ATTACKER);
        token.rescueETH(10 ether);
        assertEq(address(token).balance, 0, "REPRODUCED: ETH drained by a stranger");
        assertEq(wallet.balance, 10 ether, "REPRODUCED: fixed wallet received the ETH");
        console.log("drained to fixed wallet by arbitrary caller:", wallet);
    }

    function test_fixtureDoesNotReproduce() public {
        TokenRescueFixed token = new TokenRescueFixed(SUPPLY);
        address wallet = token.DEV_WALLET();

        token.transfer(address(token), HELD);
        vm.deal(address(token), 10 ether);

        // The stranger's calls revert on the owner gate.
        vm.prank(ATTACKER);
        vm.expectRevert();
        token.rescueERC20(address(token), HELD);
        vm.prank(ATTACKER);
        vm.expectRevert();
        token.rescueETH(10 ether);

        assertEq(token.balanceOf(address(token)), HELD, "fixed: own-token balance untouched");
        assertEq(address(token).balance, 10 ether, "fixed: ETH untouched");
        assertEq(token.balanceOf(wallet), 0, "fixed: wallet received no tokens");
        assertEq(wallet.balance, 0, "fixed: wallet received no ETH");

        // The owner can still rescue — the gate is the whole fix.
        token.rescueERC20(address(token), HELD);
        assertEq(token.balanceOf(wallet), HELD, "fixed: owner rescue still works");
        assertEq(token.balanceOf(address(token)), 0, "fixed: owner drained deliberately");
    }
}
