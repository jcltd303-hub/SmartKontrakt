// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Centralization: owner can rug (proven via prank)
/// @notice Detector: centralization. One privileged key can move the whole
///         balance / mint / pause. On a fork, pranking the owner proves
///         the CAPABILITY without needing the key: if the owner CAN do it,
///         the finding is real (trust assumption, not a bug to exploit).
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. This is a CAPABILITY proof, not an
///      unauthorized exploit -- it shows what the trusted key can do.

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

    function _readOwner() internal view returns (bool found, address owner_) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("owner()"));
        if (ok && ret.length == 32) return (true, abi.decode(ret, (address)));
        return (false, address(0));
    }

    function test_exploit() public {
        (bool found, address owner_) = _readOwner();
        require(found, "target has no owner() view -- set the owner address manually");
        console.log("owner:", owner_);

        // Attempt 1: owner drains the whole balance.
        uint256 targetBefore = target.balance;
        if (targetBefore > 0) {
            vm.prank(owner_);
            (bool drainOk,) = target.call(abi.encodeWithSignature("withdrawAll()"));
            if (drainOk && target.balance < targetBefore) {
                console.log("owner CAN drain the whole balance");
                return;
            }
        }

        // Attempt 2: owner mints unbounded tokens.
        address attackerEOA = makeAddr("attacker");
        vm.prank(owner_);
        (bool mintOk,) = target.call(
            abi.encodeWithSignature("mint(address,uint256)", attackerEOA, 1000 ether)
        );
        if (mintOk) {
            (bool balOk, bytes memory ret) =
                target.staticcall(abi.encodeWithSignature("balanceOf(address)", attackerEOA));
            if (balOk && abi.decode(ret, (uint256)) >= 1000 ether) {
                console.log("owner CAN mint unbounded tokens");
                return;
            }
        }

        // Attempt 3: owner pauses the contract.
        vm.prank(owner_);
        (bool pauseOk,) = target.call(abi.encodeWithSignature("pause()"));
        if (pauseOk) {
            (bool pausedOk, bytes memory ret) =
                target.staticcall(abi.encodeWithSignature("paused()"));
            if (pausedOk && abi.decode(ret, (bool))) {
                console.log("owner CAN pause the contract");
                return;
            }
        }

        revert("capability not proven: owner could not drain / mint / pause -- adapt the function names");
    }
}
