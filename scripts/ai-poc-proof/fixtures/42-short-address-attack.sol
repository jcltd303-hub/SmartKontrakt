// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for 42-short-address-attack (detector: short-address).
/// A payout contract that performs NO calldata-length validation: it
/// decodes whatever `calldataload` yields. An under-padded (19-byte)
/// address argument shifts the amount word left, inflating the decoded
/// amount far beyond what the caller intended; the payout is capped
/// only by the contract's balance, like an exchange hot-wallet payout.
contract ShortAddressPayout {
    receive() external payable {}

    /// VULNERABLE: no msg.data.length check before decoding `amount`.
    function withdraw(uint256 amount) public {
        uint256 pay = amount > address(this).balance ? address(this).balance : amount;
        (bool ok,) = payable(msg.sender).call{value: pay}("");
        require(ok);
    }
}
