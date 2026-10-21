// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SendLoop} from "../src/SendLoop.sol";
import {SendLoopFixed} from "../src/SendLoopFixed.sol";

// A blocking participant: it has NO receive()/fallback(), so a plain ETH send
// (and a low-level `.send`) cannot be delivered and returns false.
contract SendLoopBlocker {
    // deliberately empty
}

contract SendLoopFixtureTest is Test {

    address payable constant HONEST = payable(0x79B483371E87d664cd39491b5f06250165e4b185);

    // Storage layout of SendLoop: refundAddresses at slot 0 (length),
    // refunds mapping at slot 1.
    function _putRecipient(address c, uint256 idx, address who) internal {
        bytes32 base = keccak256(abi.encode(uint256(0)));
        vm.store(c, bytes32(uint256(base) + idx), bytes32(uint256(uint160(who))));
    }

    function _setRefund(address c, address who, uint256 amount) internal {
        bytes32 slot = keccak256(abi.encode(who, uint256(1)));
        vm.store(c, slot, bytes32(amount));
    }

    // -----------------------------------------------------------------
    // Half 1: the DoS reproduces against the vulnerable port.
    // -----------------------------------------------------------------
    function test_fixtureReproduces() public {
        SendLoop port = new SendLoop();
        SendLoopBlocker blocker = new SendLoopBlocker();

        // Put the blocker at index 0 (a participant who paid in) and an honest
        // EOA at index 1. Seed the contract with the funds to refund.
        _putRecipient(address(port), 0, address(blocker));
        _setRefund(address(port), address(blocker), 1 ether);
        _setRefund(address(port), HONEST, 1 ether);
        vm.deal(address(port), 2 ether);

        // One blocking participant reverts the whole refundAll(): nobody gets paid.
        vm.prank(address(0xA11CE));
        vm.expectRevert();
        port.refundAll();

        assertEq(HONEST.balance, 0, "honest participant blocked by the single bad recipient");
        assertEq(address(port).balance, 2 ether, "all funds held up");
    }

    // -----------------------------------------------------------------
    // Half 2: the SAME attack does not fire against the fixed variant.
    // -----------------------------------------------------------------
    function test_fixtureDoesNotReproduce() public {
        SendLoopFixed fixedC = new SendLoopFixed();
        SendLoopBlocker blocker = new SendLoopBlocker();

        _putRecipient(address(fixedC), 0, address(blocker));
        _setRefund(address(fixedC), address(blocker), 1 ether);
        _setRefund(address(fixedC), HONEST, 1 ether);
        vm.deal(address(fixedC), 2 ether);

        // The same blocking participant is present, but the batch no longer reverts.
        vm.prank(address(0xA11CE));
        fixedC.refundAll();

        assertEq(HONEST.balance, 1 ether, "fixed: honest participant is paid despite the bad recipient");
        assertEq(address(fixedC).balance, 1 ether, "fixed: only the un-payable share remains");
    }
}
