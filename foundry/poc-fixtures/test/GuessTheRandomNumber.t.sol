// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {GuessTheRandomNumber} from "../src/GuessTheRandomNumber.sol";
import {GuessTheRandomNumberFixed, GuessTheRandomNumberOracle} from "../src/GuessTheRandomNumberFixed.sol";

contract GuessTheRandomNumberFixtureTest is Test {

    bytes32 constant SEED_HASH = keccak256("seed");

    // The attacker recomputes the victim\'s "random" answer from the very same
    // public block variables the victim used.
    function _blockDerivedAnswer() internal view returns (uint8) {
        return uint8(uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), block.timestamp))));
    }

    // -----------------------------------------------------------------
    // Half 1: the attack reproduces against the vulnerable port.
    // -----------------------------------------------------------------
    function test_fixtureReproduces() public {
        vm.roll(1000);
        vm.setBlockhash(999, SEED_HASH);

        vm.deal(address(this), 5 ether);
        GuessTheRandomNumber victim = new GuessTheRandomNumber{value: 1 ether}();

        address attacker = address(0xA11CE);
        vm.deal(attacker, 1 ether);

        // Deterministic: the attacker submits exactly the victim\'s `answer`.
        uint8 n = _blockDerivedAnswer();
        vm.prank(attacker);
        victim.guess{value: 1 ether}(n);

        assertEq(address(victim).balance, 0, "attacker drained the contract");
        assertTrue(victim.isComplete(), "challenge solved -> bad randomness reproduced");
    }

    // -----------------------------------------------------------------
    // Half 2: the SAME attack does not fire against the fixed variant.
    // -----------------------------------------------------------------
    function test_fixtureDoesNotReproduce() public {
        vm.roll(1000);
        vm.setBlockhash(999, SEED_HASH);

        GuessTheRandomNumberOracle oracle = new GuessTheRandomNumberOracle();
        // The oracle\'s secret is independent of the block: make it differ from the
        // value the block-derived attack would submit.
        oracle.setValue(_blockDerivedAnswer() ^ uint8(1));

        vm.deal(address(this), 5 ether);
        GuessTheRandomNumberFixed victim = new GuessTheRandomNumberFixed{value: 1 ether}(address(oracle));

        address attacker = address(0xA11CE);
        vm.deal(attacker, 1 ether);

        // Same attack, same block-derived guess -> it does NOT match the oracle.
        uint8 n = _blockDerivedAnswer();
        vm.prank(attacker);
        victim.guess{value: 1 ether}(n);

        // The failed guess leaves the victim holding the constructor deposit plus
        // the attacker\'s failed 1 ether stake = 2 ether; no payout occurred.
        assertEq(address(victim).balance, 2 ether, "fixed: no payout, funds intact");
        assertFalse(victim.isComplete(), "fixed: block-derived attack fails");
    }
}
