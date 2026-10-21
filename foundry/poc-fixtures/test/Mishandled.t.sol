// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {Mishandled} from "../src/Mishandled.sol";
import {MishandledFixed} from "../src/MishandledFixed.sol";

/// @dev Helper: a caller whose receive() always reverts, so any ETH transfer to
///      it fails. Prefixed with the fixture name to avoid cross-fixture clashes.
contract MishandledRejectReceiver {
    uint256 public received;

    receive() external payable {
        received++;
        revert("no thanks");
    }
}

/// @title Differential fixture for dataset/unchecked_low_level_calls/mishandled.sol
contract MishandledFixtureTest is Test {
    uint256 internal constant AMOUNT = 1 ether;

    function _balanceSlot(address who) internal pure returns (bytes32) {
        // userBalances is the first (slot 0) state variable of the contract.
        return keccak256(abi.encode(who, uint256(0)));
    }

    /// @notice Attack DOES fire: the failed send is ignored, yet the caller's
    ///         recorded balance is zeroed -> funds are stranded in the contract.
    function test_fixtureReproducesUncheckedSend() public {
        Mishandled target = new Mishandled();
        MishandledRejectReceiver receiver = new MishandledRejectReceiver();

        vm.deal(address(target), AMOUNT);
        bytes32 slot = _balanceSlot(address(receiver));
        vm.store(address(target), slot, bytes32(AMOUNT));
        assertEq(uint256(vm.load(address(target), slot)), AMOUNT);

        vm.prank(address(receiver));
        target.withdrawBalance();

        // balance was zeroed even though the ETH never moved
        assertEq(uint256(vm.load(address(target), slot)), 0);
        assertEq(address(receiver).balance, 0);
        assertEq(address(target).balance, AMOUNT); // stranded
    }

    /// @notice Same attack does NOT fire on the fixed variant: the checked send
    ///         reverts, so the withdrawal (and its bookkeeping) is rolled back.
    function test_fixtureDoesNotReproduceUncheckedSend() public {
        MishandledFixed target = new MishandledFixed();
        MishandledRejectReceiver receiver = new MishandledRejectReceiver();

        vm.deal(address(target), AMOUNT);
        bytes32 slot = _balanceSlot(address(receiver));
        vm.store(address(target), slot, bytes32(AMOUNT));

        vm.prank(address(receiver));
        vm.expectRevert();
        target.withdrawBalance();

        // rolled back: balance intact, nothing delivered
        assertEq(uint256(vm.load(address(target), slot)), AMOUNT);
        assertEq(address(receiver).balance, 0);
    }
}
