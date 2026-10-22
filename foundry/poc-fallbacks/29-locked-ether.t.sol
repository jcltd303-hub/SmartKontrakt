// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Locked ether (can receive, cannot send)
/// @notice Detector: locked-ether. The contract accepts ETH (payable
///         fallback / deposit) but has NO withdrawal path -- funds sent in
///         are stuck forever.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh.
///
///      *** THIS TEMPLATE IS INVERTED ON PURPOSE. ***
///      The finding is that value CANNOT be extracted, so the reproduction is
///      the ABSENCE of a state change: the contract holds ETH and NO candidate
///      moves its balance. This harness does NOT guess a single entry point --
///      it tries every plausible exit and only reports "locked" when none of
///      them moves a wei. A call that merely RETURNS is NOT evidence either
///      way: a no-op returns successfully and moves nothing, which looks
///      identical to a real "no exit" unless we assert on the BALANCE.

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

    /// Try ONE candidate exit. In this INVERTED harness the observable we key
    /// on is a BALANCE DECREASE: a candidate that MOVES value is an EXIT, so
    /// `_attempt` returns its label and the test treats a non-empty result as
    /// NOT locked. A candidate that merely RETURNS without moving the balance
    /// is NOT an exit and is never counted.
    /// `before` is the contract's balance snapshot (with ETH held).
    function _attempt(address attacker, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        vm.prank(attacker);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        // OBSERVABLE (exit found): the balance actually DECREASED.
        if (ok && target.balance < before) return label;
        return "";
    }

    /// Returns the first candidate that MOVES the balance (i.e. an exit
    /// exists). An empty return means NO candidate moved a wei -- locked.
    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        used = _attempt(attacker, before, "withdraw()", abi.encodeWithSignature("withdraw()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "claim()", abi.encodeWithSignature("claim()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "refund()", abi.encodeWithSignature("refund()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "release()", abi.encodeWithSignature("release()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "rescue()", abi.encodeWithSignature("rescue()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "emergencyWithdraw()",
            abi.encodeWithSignature("emergencyWithdraw()")
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "selfdestruct()", abi.encodeWithSignature("selfdestruct()"));
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 2 ether);

        // Prove the contract ACCEPTS ETH -- the precondition for "locked".
        uint256 before = target.balance;
        vm.prank(attackerEOA);
        (bool sent,) = target.call{value: 1 ether}("");
        sent; // the balance assertion below is the evidence, not this flag
        assertEq(target.balance, before + 1 ether, "ETH did not land -- cannot judge locked ether");

        // OBSERVABLE (INVERTED): the contract holds ETH, and NO candidate
        // moves it. An exit would show up as a balance decrease.
        string memory exit_ = _tryEntry(attackerEOA, before + 1 ether);

        assertTrue(
            bytes(exit_).length == 0,
            string.concat(
                "NOT locked: value moved via ",
                exit_,
                " -- an exit exists, so this is not a locked-ether finding. Tried withdraw(), claim(), refund(), release(), rescue(), emergencyWithdraw(), selfdestruct()"
            )
        );
        assertGt(target.balance, 0, "no ETH present -- locked-ether cannot be judged. Tried withdraw(), claim(), refund(), release(), rescue(), emergencyWithdraw(), selfdestruct(). This does NOT establish safety.");
        console.log("locked ether reproduced: 1 ether accepted and NO candidate moved it");
    }
}
