// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {IncorrectConstructorName} from "../src/IncorrectConstructorName.sol";
import {IncorrectConstructorNameFixed} from "../src/IncorrectConstructorNameFixed.sol";

// Differential fixture for the SWC-118 incorrect-constructor-name bug.
// The vulnerable contract's would-be constructor is mis-named `IamMissing`, so
// it is an ordinary public function anyone can call to seize ownership. The
// fixed variant replaces it with a real `constructor()`.
contract IncorrectConstructorNameFixtureTest is Test {
    address internal attacker;

    function setUp() public {
        attacker = makeAddr("attacker");
    }

    // `owner` is the first state variable -> storage slot 0.
    function _owner(address a) internal view returns (address) {
        return address(uint160(uint256(vm.load(a, bytes32(uint256(0))))));
    }

    function test_fixtureReproduces() public {
        IncorrectConstructorName c = new IncorrectConstructorName();
        // IamMissing() never runs at deployment, so owner is still unset.
        assertEq(_owner(address(c)), address(0), "owner unset: IamMissing() is not a constructor");
        vm.deal(address(c), 1 ether);

        // The mis-named function is publicly callable and seizes ownership.
        vm.prank(attacker);
        c.IamMissing();
        assertEq(_owner(address(c)), attacker, "attacker seized ownership via IamMissing()");

        vm.prank(attacker);
        c.withdraw();
        assertEq(attacker.balance, 1 ether, "attacker withdrew the whole balance");
    }

    function test_fixtureDoesNotReproduce() public {
        IncorrectConstructorNameFixed c = new IncorrectConstructorNameFixed();
        address before = _owner(address(c));
        assertEq(before, address(this), "owner set once by the real constructor");
        vm.deal(address(c), 1 ether);

        // Same attack: invoke the mis-named ownership setter. It no longer exists;
        // the call lands on the empty fallback and ownership is untouched.
        vm.prank(attacker);
        address(c).call(abi.encodeWithSignature("IamMissing()"));
        assertEq(_owner(address(c)), before, "owner unchanged: no IamMissing() entrypoint");

        vm.prank(attacker);
        vm.expectRevert();
        c.withdraw();
        assertEq(address(c).balance, 1 ether, "attacker cannot withdraw");
    }
}
