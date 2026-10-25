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

    function test_reportInitializerAndOwnerCompatibility() public {
        (bool ownerOkBefore, bytes memory preOwner) = target.staticcall(abi.encodeWithSignature("owner()"));
        console2.log("owner() callable before:", ownerOkBefore);
        if (ownerOkBefore && preOwner.length >= 32) {
            console2.log("owner before:", abi.decode(preOwner, (address)));
        }
        uint256 targetBefore = target.balance;
        uint256 attackerBefore = attacker.balance;
        vm.prank(attacker);
        (bool initOk, bytes memory response) = target.call{value: 0.1 ether}(abi.encodeWithSignature("initialize()"));
        console2.log("initialize() accepted:", initOk);
        console2.log("initializer return length:", response.length);
        (bool ownerOkAfter, bytes memory postOwner) = target.staticcall(abi.encodeWithSignature("owner()"));
        console2.log("owner() callable after:", ownerOkAfter);
        if (ownerOkAfter && postOwner.length >= 32) {
            address ownerAfter = abi.decode(postOwner, (address));
            console2.log("owner after:", ownerAfter);
            assertTrue(ownerAfter != attacker, "OWNER TAKEOVER: investigate");
        }
        // No claim about ownership or safety if no owner getter is exposed.
        if (!initOk) {
            assertEq(target.balance, targetBefore, "Reverted init changed target balance");
            assertEq(attacker.balance, attackerBefore, "Reverted init changed attacker balance");
        }
    }
}
