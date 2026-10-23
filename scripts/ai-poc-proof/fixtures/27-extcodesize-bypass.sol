// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 27 (extcodesize EOA-gate bypass).
/// VULNERABLE BY DESIGN: claim() tries to keep contracts out with an
/// extcodesize == 0 check -- which is 0 for any contract still inside
/// its constructor, so a constructor-time call sails through.
contract EoaGateVault {
    uint256 public claimCount;
    mapping(address => bool) public claimed;

    function claim() external {
        uint256 size;
        address sender = msg.sender;
        assembly {
            size := extcodesize(sender)
        }
        // BUG: extcodesize is 0 during construction.
        require(size == 0, "contracts not allowed");
        claimed[msg.sender] = true;
        claimCount += 1;
        (bool ok, ) = msg.sender.call{value: 0.1 ether}("");
        require(ok, "payout failed");
    }

    receive() external payable {}
}
