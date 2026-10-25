// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";

/// @dev Minimal external ERC721 stand-in for testing unauthorized recover calls.
/// It never moves real NFTs; all state is isolated to the fork.
contract RecoveryProbe721 {
    bool public transferAttempted;
    function transferFrom(address, address, uint256) external {
        transferAttempted = true;
    }
}

contract TargetAccessForkTest is Test {
    address internal target;
    address internal outsider = address(0xBEEF1234);

    function setUp() public {
        target = vm.envAddress("POC_TARGET");
        require(target.code.length > 0, "Target has no bytecode on the fork");
        (bool ok, bytes memory result) = target.staticcall(
            abi.encodeWithSignature("isAdmin(address)", outsider)
        );
        require(ok && result.length >= 32, "Cannot verify outsider's admin status");
        require(!abi.decode(result, (bool)), "Test actor is an admin; change outsider");
    }

    function test_unauthorizedWithdrawBlocked() public {
        // vm.deal affects only the local fork; it does not transfer real ETH.
        uint256 initial = target.balance + 1 ether;
        vm.deal(target, initial);

        vm.prank(outsider);
        (bool success, ) = target.call(
            abi.encodeWithSignature("withdraw(address,uint256)", outsider, 1 ether)
        );
        assertFalse(success, "Unprivileged withdrawal succeeded");
        assertEq(target.balance, initial, "Target lost ETH to outsider");
        assertEq(outsider.balance, 0, "Outsider received ETH");
    }

    function test_unauthorizedRecoveryBlocked() public {
        RecoveryProbe721 token = new RecoveryProbe721();
        vm.prank(outsider);
        (bool success, ) = target.call(
            abi.encodeWithSignature(
                "recoverERC721(address,uint256,address)",
                address(token), uint256(1), outsider
            )
        );
        assertFalse(success, "Unprivileged NFT recovery succeeded");
        assertFalse(token.transferAttempted(), "Target called NFT transferFrom");
    }

    function test_unauthorizedMembershipChangeBlocked() public {
        (bool beforeOk, bytes memory beforeValue) = target.staticcall(
            abi.encodeWithSignature("manifoldMembershipContract()")
        );
        assertTrue(beforeOk && beforeValue.length >= 32, "Membership getter unavailable");

        vm.prank(outsider);
        (bool success, ) = target.call(
            abi.encodeWithSignature("setMembershipAddress(address)", outsider)
        );
        assertFalse(success, "Unprivileged membership change succeeded");

        (bool afterOk, bytes memory afterValue) = target.staticcall(
            abi.encodeWithSignature("manifoldMembershipContract()")
        );
        assertTrue(afterOk, "Membership getter failed afterwards");
        assertEq(afterValue, beforeValue, "Membership configuration changed");
    }

    function test_erc165InterfacePresent() public {
        (bool ok, bytes memory result) = target.staticcall(
            abi.encodeWithSignature("supportsInterface(bytes4)", bytes4(0x01ffc9a7))
        );
        assertTrue(ok && result.length >= 32, "ERC165 query failed");
        assertTrue(abi.decode(result, (bool)), "Target does not expose ERC165");
    }
}
