// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 25 (abi.encodePacked hash collision).
/// VULNERABLE BY DESIGN: authorization hashes the two string parts
/// with abi.encodePacked, so ("ab","c") and ("a","bc") are the SAME
/// voucher. The redemption ledger keys on the properly-encoded pair,
/// so it cannot tell the forgery from the original -- both redeem.
contract PackedClaim {
    // keccak256(abi.encodePacked("ab", "c")) == keccak256("abc")
    bytes32 public constant VOUCHER =
        0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45;
    mapping(bytes32 => bool) public redeemed;

    function claim(string calldata a, string calldata b) external {
        // BUG: packed hash of dynamic arguments used as the identity.
        bytes32 h = keccak256(abi.encodePacked(a, b));
        require(h == VOUCHER, "not an authorized voucher");
        bytes32 key = keccak256(abi.encode(a, b));
        require(!redeemed[key], "already redeemed");
        redeemed[key] = true;
        (bool ok, ) = msg.sender.call{value: 0.1 ether}("");
        require(ok, "payout failed");
    }

    receive() external payable {}
}
