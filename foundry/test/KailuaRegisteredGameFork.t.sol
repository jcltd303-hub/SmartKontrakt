// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";

/// @notice Read-only checks and unauthorized-call regressions for a real, registered KailuaGame.
/// @dev Address discovery comes from the treasury's live lastResolved() at the pinned fork.
///      No mainnet broadcasts, no impersonation of real users, and no synthetic account credits.
contract KailuaRegisteredGameForkTest is Test {
    address internal treasury;
    address internal actor = address(0xBEEF1234);
    address internal factory;
    address internal registered;
    address internal parent;
    address internal registeredProposer;

    bytes4 internal constant BLACKLISTED = bytes4(keccak256("Blacklisted(address,address)"));
    bytes4 internal constant UNKNOWN_GAME = bytes4(keccak256("UnknownGame()"));

    function setUp() public {
        treasury = vm.envAddress("POC_TARGET");
        require(treasury.code.length > 0, "Kailua treasury not deployed");
        factory = _readAddress(treasury, "DISPUTE_GAME_FACTORY()");
        assertGt(factory.code.length, 0, "Factory not deployed");
        registered = _readAddress(treasury, "lastResolved()");
        assertTrue(registered != address(0), "No resolved game discovered on live fork");
        assertGt(registered.code.length, 0, "Resolved game has no deployed bytecode");
        parent = _readAddress(registered, "parentGame()");
        assertGt(parent.code.length, 0, "Resolved game's parent has no code");
        registeredProposer = _readAddressArg(treasury, "proposerOf(address)", registered);
        assertTrue(registeredProposer != address(0), "Resolved game not registered by treasury");
        assertFalse(_readBool(treasury, "isProposing()"), "Unexpected in-progress proposal at snapshot");
        assertEq(_readUintArg(treasury, "eliminationRound(address)", actor), 0);
    }

    function _readAddress(address c, string memory sig) internal view returns (address value) {
        (bool ok, bytes memory data) = c.staticcall(abi.encodeWithSignature(sig));
        require(ok && data.length == 32, "address getter unavailable");
        value = abi.decode(data, (address));
    }
    function _readAddressArg(address c, string memory sig, address arg) internal view returns (address value) {
        (bool ok, bytes memory data) = c.staticcall(abi.encodeWithSignature(sig, arg));
        require(ok && data.length == 32, "address mapping getter unavailable");
        value = abi.decode(data, (address));
    }
    function _readUint(address c, string memory sig) internal view returns (uint256 value) {
        (bool ok, bytes memory data) = c.staticcall(abi.encodeWithSignature(sig));
        require(ok && data.length == 32, "uint getter unavailable");
        value = abi.decode(data, (uint256));
    }
    function _readUintArg(address c, string memory sig, address arg) internal view returns (uint256 value) {
        (bool ok, bytes memory data) = c.staticcall(abi.encodeWithSignature(sig, arg));
        require(ok && data.length == 32, "uint mapping getter unavailable");
        value = abi.decode(data, (uint256));
    }
    function _readBool(address c, string memory sig) internal view returns (bool value) {
        (bool ok, bytes memory data) = c.staticcall(abi.encodeWithSignature(sig));
        require(ok && data.length == 32, "boolean getter unavailable");
        value = abi.decode(data, (bool));
    }
    function _selector(bytes memory data) internal pure returns (bytes4 out) {
        if (data.length < 4) return bytes4(0);
        assembly { out := mload(add(data, 32)) }
    }

    function test_realGameHasProposerAndKailuaIdentity() public view {
        uint256 index = _readUint(registered, "gameIndex()");
        uint256 createdAt = _readUint(registered, "createdAt()");
        uint256 status = _readUint(registered, "status()");
        address embeddedTreasury = _readAddress(registered, "KAILUA_TREASURY()");
        console2.log("Registered game:", registered);
        console2.log("Registered proposer:", registeredProposer);
        console2.log("Registered parent:", parent);
        console2.log("Game index:", index);
        console2.log("Game createdAt:", createdAt);
        console2.log("Game status:", status);
        assertEq(embeddedTreasury, treasury, "Registered game's treasury mismatch");
        assertEq(_readUint(registered, "gameType()"), 1337, "Unexpected game type");
        assertGt(createdAt, 0, "Discovered game not initialized");
    }

    function test_factoryGameIndexMapsToRegisteredClone() public view {
        uint256 index = _readUint(registered, "gameIndex()");
        (bool ok, bytes memory data) = factory.staticcall(abi.encodeWithSignature("gameAtIndex(uint256)", index));
        console2.log("Factory gameAtIndex readable:", ok);
        assertTrue(ok && data.length == 96, "Factory index lookup unavailable");
        (uint32 gameType, uint64 timestamp, address indexedGame) = abi.decode(data, (uint32, uint64, address));
        console2.log("Factory gameAtIndex:", indexedGame);
        console2.log("Factory timestamp:", timestamp);
        assertEq(indexedGame, registered, "Registered game does not match factory index");
        assertEq(uint256(gameType), 1337, "Unexpected factory game type");
        assertGt(timestamp, 0);
    }

    function test_realGameHasParentRegistration() public view {
        uint256 count = _readUint(parent, "childCount()");
        console2.log("Parent childCount:", count);
        assertGt(count, 0, "Registered game parent has no children");
        // A registered game must be present in its parent's child set.
        // Cap enumeration to prevent unbounded work on a large existing tournament.
        assertLe(count, 2048, "Too many children to enumerate; use event-indexed pagination");
        bool found;
        for (uint256 i; i < count; ++i) {
            (bool ok, bytes memory data) = parent.staticcall(abi.encodeWithSignature("children(uint256)", i));
            require(ok && data.length == 32, "parent.children lookup unavailable");
            if (abi.decode(data, (address)) == registered) { found = true; break; }
        }
        assertTrue(found, "Registered game is not in parent child list");
    }

    function test_cannotAppendForgedChildToRealParent() public {
        uint256 countBefore = _readUint(parent, "childCount()");
        vm.prank(actor);
        (bool success, bytes memory revertData) = parent.call(abi.encodeWithSignature("appendChild()"));
        assertFalse(success, "Unprivileged actor appended child to real parent");
        assertEq(_selector(revertData), UNKNOWN_GAME, "Unexpected registration guard");
        assertEq(_readUint(parent, "childCount()"), countBefore, "Forged append changed parent list");
    }

    function test_cannotReappendExistingGameWhenTreasuryNotProposing() public {
        uint256 countBefore = _readUint(parent, "childCount()");
        // Simulate caller identity on local fork without running any real game code.
        vm.prank(registered);
        (bool success, bytes memory revertData) = parent.call(abi.encodeWithSignature("appendChild()"));
        assertFalse(success, "An old registered game was allowed to register another child");
        assertEq(_selector(revertData), UNKNOWN_GAME, "Unexpected registration guard");
        assertEq(_readUint(parent, "childCount()"), countBefore, "Parent list grew outside proposal creation");
    }

    function test_cannotEliminateRealRegisteredGameWithoutParentAuthority() public {
        uint256 bondBefore = _readUintArg(treasury, "paidBonds(address)", registeredProposer);
        uint256 roundBefore = _readUintArg(treasury, "eliminationRound(address)", registeredProposer);
        uint256 rewardsBefore = _readUintArg(treasury, "eliminationRewards(address)", actor);
        uint256 treasuryBefore = treasury.balance;
        vm.prank(actor);
        (bool success, bytes memory revertData) = treasury.call(
            abi.encodeWithSignature("eliminate(address,address)", registered, actor)
        );
        assertFalse(success, "Unprivileged actor eliminated a real registered game");
        assertEq(_selector(revertData), BLACKLISTED, "Unexpected elimination authority check");
        assertEq(_readUintArg(treasury, "paidBonds(address)", registeredProposer), bondBefore);
        assertEq(_readUintArg(treasury, "eliminationRound(address)", registeredProposer), roundBefore);
        assertEq(_readUintArg(treasury, "eliminationRewards(address)", actor), rewardsBefore);
        assertEq(treasury.balance, treasuryBefore, "Unauthorized elimination moved funds");
    }
}
