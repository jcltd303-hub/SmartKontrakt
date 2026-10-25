// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";

/// @notice Evidence-only fork tests for Ronin KailuaTreasury v1.2.0.
/// @dev Never broadcasts; uses an unprivileged actor and snapshots key state.
contract KailuaInitializerCompatibilityForkTest is Test {
    address internal target;
    address internal outsider = address(0xBEEF1234);

    bytes4 constant BLOCK_MISMATCH = bytes4(keccak256("BlockNumberMismatch(uint256,uint256)"));
    bytes4 constant BLACKLISTED = bytes4(keccak256("Blacklisted(address,address)"));
    bytes4 constant ALREADY_INITIALIZED = bytes4(keccak256("AlreadyInitialized()"));
    bytes4 constant INCORRECT_BOND_AMOUNT = bytes4(keccak256("IncorrectBondAmount()"));
    bytes4 constant BAD_AUTH = bytes4(keccak256("BadAuth()"));

    function setUp() public {
        target = vm.envAddress("POC_TARGET");
        require(target.code.length > 0, "Missing target code at fork block");
        vm.deal(outsider, 2 ether);
    }

    function _readUint(string memory signature) internal view returns (uint256 n) {
        (bool ok, bytes memory result) = target.staticcall(abi.encodeWithSignature(signature));
        require(ok && result.length == 32, "Expected Kailua uint getter unavailable");
        n = abi.decode(result, (uint256));
    }

    function _readAddress(string memory signature) internal view returns (address a) {
        (bool ok, bytes memory result) = target.staticcall(abi.encodeWithSignature(signature));
        require(ok && result.length == 32, "Expected Kailua address getter unavailable");
        a = abi.decode(result, (address));
    }

    function _selector(bytes memory data) internal pure returns (bytes4 selector) {
        if (data.length < 4) return bytes4(0);
        assembly { selector := mload(add(data, 32)) }
    }

    function _reportError(bytes memory revertData) internal pure {
        bytes4 selector = _selector(revertData);
        console2.log("Revert returndata bytes:", revertData.length);
        console2.logBytes4(selector);
        if (selector == BLOCK_MISMATCH && revertData.length == 68) {
            uint256 anchored;
            uint256 initialized;
            assembly {
                anchored := mload(add(revertData, 36))
                initialized := mload(add(revertData, 68))
            }
            console2.log("BlockNumberMismatch. anchored:", anchored);
            console2.log("BlockNumberMismatch. initialized:", initialized);
        } else if (selector == BLACKLISTED && revertData.length == 68) {
            address source;
            address expected;
            assembly {
                source := mload(add(revertData, 36))
                expected := mload(add(revertData, 68))
            }
            console2.log("Blacklisted. source:", source);
            console2.log("Blacklisted. expected:", expected);
        } else if (selector == ALREADY_INITIALIZED) {
            console2.log("AlreadyInitialized()");
        } else if (selector == INCORRECT_BOND_AMOUNT) {
            console2.log("IncorrectBondAmount()");
        } else if (selector == BAD_AUTH) {
            console2.log("BadAuth()");
        } else {
            console2.log("Unknown error selector; full data follows:");
            console2.logBytes(revertData);
        }
    }

    function test_confirmRoninKailuaIdentity() public view {
        assertEq(_readAddress("KAILUA_TREASURY()"), target, "Not self-referential Kailua treasury");
        assertEq(_readUint("GAME_TYPE()"), 1337, "Unexpected Kailua game type");
        // Ownable/proxy methods were part of a supplied hypothetical PoC, not this ABI.
        (bool ownerOk,) = target.staticcall(abi.encodeWithSignature("owner()"));
        assertFalse(ownerOk, "Unexpected Ownable interface; revisit hypothesis");
    }

    function test_decodePayableInitializerRevertAndStateInvariants() public {
        uint256 createdAtBefore = _readUint("createdAt()");
        uint256 gameIndexBefore = _readUint("gameIndex()");
        uint256 childCountBefore = _readUint("childCount()");
        uint256 bondBefore = _readUint("participationBond()");
        uint256 targetBalanceBefore = target.balance;
        uint256 outsiderBalanceBefore = outsider.balance;

        console2.log("Treasury initialized createdAt (pre):", createdAtBefore);
        console2.log("Treasury gameIndex (pre):", gameIndexBefore);
        console2.log("Treasury participationBond (pre):", bondBefore);

        vm.prank(outsider);
        (bool succeeded, bytes memory result) = target.call{value: 0.1 ether}(
            abi.encodeWithSignature("initialize()")
        );
        console2.log("initialize payable succeeded:", succeeded);
        _reportError(result);
        // Unexpected success is NOT automatically an exploit, but must be investigated.
        assertFalse(succeeded, "Unexpected initializer success; review protocol semantics");
        assertEq(_readUint("createdAt()"), createdAtBefore, "Initializer mutated createdAt");
        assertEq(_readUint("gameIndex()"), gameIndexBefore, "Initializer mutated gameIndex");
        assertEq(_readUint("childCount()"), childCountBefore, "Initializer mutated childCount");
        assertEq(_readUint("participationBond()"), bondBefore, "Initializer mutated participationBond");
        assertEq(target.balance, targetBalanceBefore, "Initializer transferred ETH to target");
        assertEq(outsider.balance, outsiderBalanceBefore, "Initializer charged outsider");
    }

    function test_unprivilegedBondSetterRejected() public {
        uint256 bondBefore = _readUint("participationBond()");
        vm.prank(outsider);
        (bool success, bytes memory err) = target.call(
            abi.encodeWithSignature("setParticipationBond(uint256)", 1 wei)
        );
        console2.log("setParticipationBond succeeded:", success);
        if (!success) _reportError(err);
        assertFalse(success, "Unprivileged actor changed participation bond");
        assertEq(_readUint("participationBond()"), bondBefore, "Bond changed");
    }

    function test_unprivilegedVanguardSetterRejected() public {
        address current = _readAddress("vanguard()");
        vm.prank(outsider);
        (bool success, bytes memory err) = target.call(
            abi.encodeWithSignature("assignVanguard(address,uint64)", outsider, uint64(1))
        );
        console2.log("assignVanguard succeeded:", success);
        if (!success) _reportError(err);
        assertFalse(success, "Unprivileged actor set vanguard");
        assertEq(_readAddress("vanguard()"), current, "Vanguard changed");
    }
}
