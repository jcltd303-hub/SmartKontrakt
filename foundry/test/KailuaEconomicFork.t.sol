// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";

/// @notice Minimal fake child: only the parentGame getter used by the real treasury.
contract KailuaFakeChild {
    address public parentGame;
    constructor(address parent_) { parentGame = parent_; }
}

/// @notice A payout receiver that attempts to reenter the claimed treasury function.
/// @dev This is only used with fork-local synthetic credits.
contract KailuaPayoutProbe {
    address public immutable treasury;
    bytes public callback;
    bool public attemptReentry;
    bool public rejectPayment;
    uint256 public received;
    uint256 public callbacks;
    bool public reenteredSuccessfully;

    constructor(address treasury_) { treasury = treasury_; }

    function configure(bytes memory selectorData, bool reenter_, bool reject_) external {
        callback = selectorData;
        attemptReentry = reenter_;
        rejectPayment = reject_;
    }

    function claimRewards() external {
        (bool success,) = treasury.call(abi.encodeWithSignature("claimEliminationRewards()"));
        require(success, "reward claim failed");
    }

    function claimBond() external {
        (bool success,) = treasury.call(abi.encodeWithSignature("claimProposerBond()"));
        require(success, "bond claim failed");
    }

    receive() external payable {
        if (rejectPayment) revert("reject payout");
        received += msg.value;
        callbacks += 1;
        if (attemptReentry) {
            attemptReentry = false;
            (bool success,) = treasury.call(callback);
            reenteredSuccessfully = success;
        }
    }
}

/// @title KailuaTreasury economic-path regression checks
/// @notice Calls the *deployed* treasury on a pinned fork, using real getters and selectors.
/// @dev Synthetic credit tests use vm.store and vm.deal and are NOT evidence of live user credits.
contract KailuaEconomicForkTest is Test {
    address internal target;
    address internal actor = address(0xBEEF1234);

    bytes4 constant INCORRECT_BOND = bytes4(keccak256("IncorrectBondAmount()"));
    bytes4 constant NO_CREDIT = bytes4(keccak256("NoCreditToClaim()"));
    bytes4 constant NOT_PROPOSED = bytes4(keccak256("NotProposed()"));
    bytes4 constant BLACKLISTED = bytes4(keccak256("Blacklisted(address,address)"));
    bytes4 constant BOND_TRANSFER_FAILED = bytes4(keccak256("BondTransferFailed()"));

    function setUp() public {
        target = vm.envAddress("POC_TARGET");
        require(target.code.length > 0, "target missing on fork");
        vm.deal(actor, 3 ether);
        // Economic tests use a caller with no existing on-chain bond/credit.
        assertEq(_readMapping("paidBonds(address)", actor), 0, "actor has an existing paid bond");
        assertEq(_readMapping("eliminationRewards(address)", actor), 0, "actor has existing rewards");
    }

    function _selector(bytes memory data) internal pure returns (bytes4 out) {
        if (data.length < 4) return bytes4(0);
        assembly { out := mload(add(data, 32)) }
    }

    function _readUint(string memory signature) internal view returns (uint256 value) {
        (bool ok, bytes memory result) = target.staticcall(abi.encodeWithSignature(signature));
        require(ok && result.length == 32, "treasury getter unavailable");
        value = abi.decode(result, (uint256));
    }

    function _readAddress(string memory signature) internal view returns (address value) {
        (bool ok, bytes memory result) = target.staticcall(abi.encodeWithSignature(signature));
        require(ok && result.length == 32, "treasury address getter unavailable");
        value = abi.decode(result, (address));
    }

    function _readMapping(string memory signature, address who) internal view returns (uint256 value) {
        (bool ok, bytes memory result) = target.staticcall(abi.encodeWithSignature(signature, who));
        require(ok && result.length == 32, "treasury credit getter unavailable");
        value = abi.decode(result, (uint256));
    }

    function _readMappingAddress(string memory signature, address who) internal view returns (address value) {
        (bool ok, bytes memory result) = target.staticcall(abi.encodeWithSignature(signature, who));
        require(ok && result.length == 32, "treasury proposer getter unavailable");
        value = abi.decode(result, (address));
    }

    /// @dev Synthetic credit injection only: find the mapping entry's actual slot by recording
    /// a public getter's SLOAD, rather than guessing the contract's storage layout.
    function _injectCredit(string memory getter, address beneficiary, uint256 amount) internal {
        vm.record();
        uint256 old = _readMapping(getter, beneficiary);
        assertEq(old, 0, "credit injection requires a zero starting balance");
        (bytes32[] memory reads,) = vm.accesses(target);
        assertEq(reads.length, 1, "unexpected storage layout or getter");
        vm.store(target, reads[0], bytes32(amount));
        assertEq(_readMapping(getter, beneficiary), amount, "synthetic credit injection failed");
    }

    function test_uncreditedEliminationRewardClaimCannotDrainPrefundedTreasury() public {
        // Real contract, simulated *unallocated* funds. No live balances are modified.
        vm.deal(target, 4 ether);
        uint256 targetBefore = target.balance;
        uint256 actorBefore = actor.balance;
        vm.startPrank(actor);
        (bool ok,) = target.call(abi.encodeWithSignature("claimEliminationRewards()"));
        assertTrue(ok, "zero-credit rewards claim should be a successful no-op");
        (bool repeated,) = target.call(abi.encodeWithSignature("claimEliminationRewards()"));
        vm.stopPrank();
        assertTrue(repeated, "second empty rewards claim should be a no-op");
        assertEq(_readMapping("eliminationRewards(address)", actor), 0);
        assertEq(target.balance, targetBefore, "uncredited reward claim depleted treasury");
        assertEq(actor.balance, actorBefore, "uncredited actor gained ETH");
    }

    function test_uncreditedProposerBondClaimReverts() public {
        vm.deal(target, 4 ether);
        uint256 targetBefore = target.balance;
        uint256 actorBefore = actor.balance;
        vm.prank(actor);
        (bool ok, bytes memory revertData) = target.call(abi.encodeWithSignature("claimProposerBond()"));
        assertFalse(ok, "uncredited bond claim unexpectedly succeeded");
        assertEq(_selector(revertData), NO_CREDIT, "unexpected bond rejection");
        assertEq(_readMapping("paidBonds(address)", actor), 0);
        assertEq(target.balance, targetBefore);
        assertEq(actor.balance, actorBefore);
    }

    function test_underbondedProposalRevertsAndRefundsAllEth() public {
        uint256 bond = _readUint("participationBond()");
        assertGt(bond, 1 wei, "bond should be positive");
        assertLt(bond, actor.balance, "actor cannot cover configured bond");
        uint256 targetBefore = target.balance;
        uint256 actorBefore = actor.balance;
        vm.prank(actor);
        (bool ok, bytes memory err) = target.call{value: bond - 1}(
            abi.encodeWithSignature("propose(bytes32,bytes)", bytes32(0), hex"01")
        );
        assertFalse(ok, "underbonded proposal unexpectedly accepted");
        assertEq(_selector(err), INCORRECT_BOND, "wrong underbond error");
        assertEq(_readMapping("paidBonds(address)", actor), 0, "revert credited unpaid bond");
        assertEq(target.balance, targetBefore, "revert retained proposal ETH");
        assertEq(actor.balance, actorBefore, "revert charged proposer");
    }

    function test_invalidProposalWithFullBondDoesNotRetainCredit() public {
        uint256 bond = _readUint("participationBond()");
        uint256 targetBefore = target.balance;
        uint256 actorBefore = actor.balance;
        address factory = _readAddress("DISPUTE_GAME_FACTORY()");
        (bool countOk, bytes memory countRaw) = factory.staticcall(abi.encodeWithSignature("gameCount()"));
        require(countOk && countRaw.length == 32, "dispute-game factory game count unavailable");
        uint256 gamesBefore = abi.decode(countRaw, (uint256));
        vm.prank(actor);
        (bool ok, bytes memory revertData) = target.call{value: bond}(
            abi.encodeWithSignature("propose(bytes32,bytes)", bytes32(0), hex"01")
        );
        console2.log("malformed full-bond proposal accepted:", ok);
        if (!ok) {
            console2.logBytes4(_selector(revertData));
        }
        assertFalse(ok, "malformed 1-byte proposal unexpectedly accepted");
        assertEq(_readMapping("paidBonds(address)", actor), 0, "reverted proposal retained credit");
        assertEq(_readMappingAddress("lastProposal(address)", actor), address(0));
        assertEq(target.balance, targetBefore);
        assertEq(actor.balance, actorBefore);
        (countOk, countRaw) = factory.staticcall(abi.encodeWithSignature("gameCount()"));
        require(countOk && countRaw.length == 32, "gameCount() failed after reverted proposal");
        assertEq(abi.decode(countRaw, (uint256)), gamesBefore, "reverted proposal changed factory count");
    }

    function test_eliminateRequiresActualParent() public {
        KailuaFakeChild candidate = new KailuaFakeChild(address(0xCAFE));
        uint256 targetBefore = target.balance;
        vm.prank(actor);
        (bool ok, bytes memory err) = target.call(abi.encodeWithSignature("eliminate(address,address)", address(candidate), actor));
        assertFalse(ok, "non-parent actor eliminated candidate");
        assertEq(_selector(err), BLACKLISTED, "missing parent authorization");
        assertEq(target.balance, targetBefore);
        assertEq(_readMapping("eliminationRewards(address)", actor), 0);
    }

    function test_eliminateUnregisteredChildRejectedEvenWithMatchingParent() public {
        KailuaFakeChild candidate = new KailuaFakeChild(actor);
        vm.prank(actor);
        (bool ok, bytes memory err) = target.call(abi.encodeWithSignature("eliminate(address,address)", address(candidate), actor));
        assertFalse(ok, "unregistered child passed eliminated-proposer lookup");
        assertEq(_selector(err), NOT_PROPOSED, "expected proposer registration guard");
        assertEq(_readMapping("eliminationRewards(address)", actor), 0);
    }

    function test_unregisteredResolutionCannotCreditRewards() public {
        address lastResolvedBefore = _readAddress("lastResolved()");
        vm.prank(actor);
        (bool ok, bytes memory err) = target.call(abi.encodeWithSignature("updateLastResolved()"));
        assertFalse(ok, "unknown proposal updated last resolved game");
        assertEq(_selector(err), NOT_PROPOSED, "expected proposer registration guard");
        assertEq(_readAddress("lastResolved()"), lastResolvedBefore);
        assertEq(_readMapping("eliminationRewards(address)", actor), 0);
    }

    function test_syntheticRewardCreditPaysOnceAndBlocksReentrantClaim() public {
        KailuaPayoutProbe claimant = new KailuaPayoutProbe(target);
        _injectCredit("eliminationRewards(address)", address(claimant), 0.4 ether);
        vm.deal(target, 4 ether);
        claimant.configure(abi.encodeWithSignature("claimEliminationRewards()"), true, false);
        uint256 beforeBalance = target.balance;
        claimant.claimRewards();
        assertEq(claimant.received(), 0.4 ether, "synthetic claimant not paid once");
        assertEq(claimant.callbacks(), 1, "unexpected reward payout count");
        assertFalse(claimant.reenteredSuccessfully(), "reentrancy unexpectedly succeeded");
        assertEq(target.balance, beforeBalance - 0.4 ether);
        assertEq(_readMapping("eliminationRewards(address)", address(claimant)), 0);
        claimant.claimRewards();
        assertEq(claimant.received(), 0.4 ether, "repeated claim paid again");
    }

    function test_syntheticBondCreditPaysOnceAndBlocksReentrantClaim() public {
        KailuaPayoutProbe claimant = new KailuaPayoutProbe(target);
        _injectCredit("paidBonds(address)", address(claimant), 0.4 ether);
        vm.deal(target, 4 ether);
        claimant.configure(abi.encodeWithSignature("claimProposerBond()"), true, false);
        uint256 beforeBalance = target.balance;
        claimant.claimBond();
        assertEq(claimant.received(), 0.4 ether, "synthetic bond not paid once");
        assertEq(claimant.callbacks(), 1, "unexpected bond callback count");
        assertFalse(claimant.reenteredSuccessfully(), "bond reentrancy succeeded");
        assertEq(target.balance, beforeBalance - 0.4 ether);
        assertEq(_readMapping("paidBonds(address)", address(claimant)), 0);
        (bool repeat,) = address(claimant).call(abi.encodeWithSignature("claimBond()"));
        assertFalse(repeat, "spent bond claimed a second time");
    }

    function test_syntheticFailedRewardPayoutDoesNotEraseCredit() public {
        KailuaPayoutProbe claimant = new KailuaPayoutProbe(target);
        _injectCredit("eliminationRewards(address)", address(claimant), 0.4 ether);
        vm.deal(target, 4 ether);
        claimant.configure("", false, true);
        uint256 targetBefore = target.balance;
        (bool ok, bytes memory err) = address(claimant).call(abi.encodeWithSignature("claimRewards()"));
        assertFalse(ok, "reward claim should revert when receiver rejects ETH");
        // The failed nested claim is wrapped by claimant.require, so outer return data is not
        // necessarily BondTransferFailed(); verify rollback rather than error selector.
        assertGt(err.length, 0, "expected revert data");
        assertEq(_readMapping("eliminationRewards(address)", address(claimant)), 0.4 ether);
        assertEq(target.balance, targetBefore);
        assertEq(address(claimant).balance, 0);
    }
}
