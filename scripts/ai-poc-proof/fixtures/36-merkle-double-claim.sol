// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 36 (Merkle double-claim).
/// VULNERABLE BY DESIGN: claim() verifies the Merkle proof but never
/// records that the leaf was claimed -- the SAME proof pays out twice
/// (three times, four times...). The suite uses a single-leaf tree
/// (root == leaf, empty proof) for the template's makeAddr("attacker")
/// claimant; the runner computes the root from the manifest values.
contract MerkleAirdrop {
    bytes32 public root;

    constructor(bytes32 root_) {
        root = root_;
    }

    function claim(bytes32[] calldata proof, uint256 amount) external {
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computed = computed < proof[i]
                ? keccak256(abi.encodePacked(computed, proof[i]))
                : keccak256(abi.encodePacked(proof[i], computed));
        }
        require(computed == root, "invalid proof");
        // BUG: no claimed[leaf] record -- replayable.
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "payout failed");
    }

    receive() external payable {}
}
