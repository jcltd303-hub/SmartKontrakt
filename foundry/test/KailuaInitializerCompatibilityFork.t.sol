// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test, console2} from "forge-std/Test.sol";

contract KailuaInitializerCompatibilityForkTest is Test {
    address target;
    address attacker = address(0xBEEF1234);
    function setUp() public {
        target = vm.envAddress("POC_TARGET");
        require(target.code.length > 0, "Missing target");
        vm.deal(attacker, 1 ether);
    }

    function test_kailuaInitializerCannotTakeOverTarget() public {
        (bool beforeOk, bytes memory beforeData) = target.staticcall(abi.encodeWithSignature("owner()"));
        assertTrue(beforeOk && beforeData.length >= 32, "Owner getter unavailable");
        address ownerBefore = abi.decode(beforeData, (address));
        uint256 balanceBefore = target.balance;
        vm.prank(attacker);
        (bool accepted, bytes memory result) = target.call{value: 0.1 ether}(abi.encodeWithSignature("initialize()"));
        console2.log("initialize() accepted:", accepted);
        console2.log("revert/return bytes:", result.length);
        (bool afterOk, bytes memory afterData) = target.staticcall(abi.encodeWithSignature("owner()"));
        assertTrue(afterOk && afterData.length >= 32, "Owner getter unavailable after call");
        address ownerAfter = abi.decode(afterData, (address));
        assertEq(ownerAfter, ownerBefore, "Initializer changed contract owner");
        assertTrue(ownerAfter != attacker, "Attacker became owner");
        assertFalse(accepted, "Unexpected success: inspect initializer entrypoint");
        assertEq(target.balance, balanceBefore, "Unexpected ETH transfer to target");
    }
}
