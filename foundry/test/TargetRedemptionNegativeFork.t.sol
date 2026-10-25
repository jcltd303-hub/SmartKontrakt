// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test} from "forge-std/Test.sol";

/// @notice Negative-path checks against actual deployed bytecode on a pinned mainnet fork.
/// @dev All transactions remain fork-local; no broadcast.
contract TargetRedemptionNegativeForkTest is Test {
    address target;
    address outsider = address(0xBEEF1234);

    function setUp() public {
        target = vm.envAddress("POC_TARGET");
        require(target.code.length != 0, "Missing target code");
    }

    function test_invalidCampaignBurnRedeemRevertsWithoutFundsMovement() public {
        uint256 beforeBalance = target.balance;
        vm.deal(outsider, 2 ether);
        vm.prank(outsider);
        // Empty BurnToken[] encoded as an empty dynamic tuple-array (4 dynamic struct fields).
        (bool ok,) = target.call{value: 1 ether}(
            abi.encodeWithSignature(
                "burnRedeem(address,uint256,uint32,(address,uint256,uint256,uint256,bytes32[])[])",
                address(0x1234), uint256(type(uint56).max), uint32(1),
                new bytes(0)
            )
        );
        // This call is intentionally malformed; EVM must not retain payment.
        assertFalse(ok, "Malformed redemption unexpectedly succeeded");
        assertEq(target.balance, beforeBalance, "Reverted redemption retained payment");
        assertEq(outsider.balance, 2 ether, "Reverted redemption debited outsider");
    }

    function test_invalidERC721CallbackCannotMint() public {
        vm.prank(outsider);
        (bool ok,) = target.call(
            abi.encodeWithSignature(
                "onERC721Received(address,address,uint256,bytes4)",
                outsider, outsider, uint256(1), bytes4(0)
            )
        );
        assertFalse(ok, "Invalid ERC721 callback accepted");
    }

    function test_invalidERC1155CallbackCannotMint() public {
        vm.prank(outsider);
        (bool ok,) = target.call(
            abi.encodeWithSignature(
                "onERC1155Received(address,address,uint256,uint256,bytes)",
                outsider, outsider, uint256(1), uint256(1), hex"01"
            )
        );
        assertFalse(ok, "Malformed ERC1155 callback accepted");
    }

    function test_invalidERC1155BatchCallbackCannotMint() public {
        uint256[] memory ids = new uint256[](1);
        uint256[] memory values = new uint256[](1);
        ids[0] = 1; values[0] = 1;
        vm.prank(outsider);
        (bool ok,) = target.call(
            abi.encodeWithSignature(
                "onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)",
                outsider, outsider, ids, values, hex"01"
            )
        );
        assertFalse(ok, "Malformed ERC1155 batch callback accepted");
    }
}
