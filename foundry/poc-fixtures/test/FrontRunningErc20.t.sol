// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {FrontRunningErc20} from "../src/FrontRunningErc20.sol";
import {FrontRunningErc20Fixed} from "../src/FrontRunningErc20Fixed.sol";

contract FrontRunningErc20FixtureTest is Test {

    address constant OWNER = address(0x0117);
    address constant ATTACKER = address(0xA11CE);

    // -----------------------------------------------------------------
    // Half 1: the front-running reproduces against the vulnerable port.
    // -----------------------------------------------------------------
    function test_fixtureReproduces() public {
        vm.prank(OWNER);
        FrontRunningErc20 token = new FrontRunningErc20(1000);

        // Owner grants the attacker an allowance of 100.
        vm.prank(OWNER);
        token.approve(ATTACKER, 100);
        assertEq(token.allowance(OWNER, ATTACKER), 100);

        // Owner decides to CHANGE the allowance to 50 (a pending tx).
        // The attacker front-runs it and spends the full OLD allowance first.
        vm.prank(ATTACKER);
        token.transferFrom(OWNER, ATTACKER, 100);

        // The owner's allowance-change tx now lands.
        vm.prank(OWNER);
        token.approve(ATTACKER, 50);

        // The attacker spends the NEW allowance too.
        vm.prank(ATTACKER);
        token.transferFrom(OWNER, ATTACKER, 50);

        // Double-spend: 150 taken even though the owner intended a 50 limit.
        assertEq(token.balanceOf(ATTACKER), 150, "attacker took old (100) + new (50) allowance");
        assertEq(token.balanceOf(OWNER), 850, "owner lost 150, not 100");
        console.log("FrontRunningErc20: double-spend of", token.balanceOf(ATTACKER));
    }

    // -----------------------------------------------------------------
    // Half 2: the SAME attack does not fire against the fixed variant.
    // -----------------------------------------------------------------
    function test_fixtureDoesNotReproduce() public {
        vm.prank(OWNER);
        FrontRunningErc20Fixed token = new FrontRunningErc20Fixed(1000);

        vm.prank(OWNER);
        token.approve(ATTACKER, 100);

        // Same front-run: spend the old allowance of 100.
        vm.prank(ATTACKER);
        token.transferFrom(OWNER, ATTACKER, 100);


        // The owner reduces the allowance to 50 via a RELATIVE change. Because the
        // attacker already spent the whole 100, the reduction now underflows and
        // REVERTS - no fresh 50 is ever granted.
        vm.prank(OWNER);
        vm.expectRevert();
        token.decreaseAllowance(ATTACKER, 50);

        // No fresh allowance was granted, so the double-spend cannot happen.
        assertEq(token.balanceOf(ATTACKER), 100, "fixed: attacker only gets the originally approved 100");
        assertEq(token.balanceOf(OWNER), 900, "fixed: owner keeps 900");
    }
}
