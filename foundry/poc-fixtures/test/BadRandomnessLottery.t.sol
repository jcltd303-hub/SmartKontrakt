// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {BadRandomnessLottery} from "../src/BadRandomnessLottery.sol";
import {BadRandomnessLotteryFixed, BadRandomnessLotteryOracle} from "../src/BadRandomnessLotteryFixed.sol";

contract BadRandomnessLotteryFixtureTest is Test {

    // -----------------------------------------------------------------
    // Half 1: the attack reproduces against the vulnerable port.
    // -----------------------------------------------------------------
    function test_fixtureReproduces() public {
        BadRandomnessLottery lottery = new BadRandomnessLottery();

        address attacker = address(0xA11CE);
        vm.deal(attacker, 1 ether);

        // The bettor picks an EVEN block, so `block.number % 2 == 0` is guaranteed.
        vm.roll(100);
        vm.prank(attacker);
        lottery.makeBet{value: 1 ether}();

        // Deterministic win: the stake is refunded, the contract keeps nothing.
        assertEq(address(lottery).balance, 0, "attacker wins deterministically (stake refunded)");
        assertEq(attacker.balance, 1 ether, "attacker is not out of pocket");

        // Control: an odd block makes an honest bettor lose.
        vm.roll(101);
        address victim = address(0xB0B);
        vm.deal(victim, 1 ether);
        vm.prank(victim);
        lottery.makeBet{value: 1 ether}();
        assertEq(address(lottery).balance, 1 ether, "odd block -> bettor loses");
    }

    // -----------------------------------------------------------------
    // Half 2: the SAME attack does not fire against the fixed variant.
    // -----------------------------------------------------------------
    function test_fixtureDoesNotReproduce() public {
        BadRandomnessLotteryOracle oracle = new BadRandomnessLotteryOracle();
        oracle.setValue(false); // the oracle says: you lose
        BadRandomnessLotteryFixed lottery = new BadRandomnessLotteryFixed(address(oracle));

        address attacker = address(0xA11CE);
        vm.deal(attacker, 1 ether);

        // Same attack: bet in an EVEN block.
        vm.roll(100);
        vm.prank(attacker);
        lottery.makeBet{value: 1 ether}();

        // The block parity no longer decides -> no deterministic win.
        assertEq(address(lottery).balance, 1 ether, "fixed: even block no longer wins");
        assertEq(attacker.balance, 0, "fixed: attacker lost the stake");
    }
}
