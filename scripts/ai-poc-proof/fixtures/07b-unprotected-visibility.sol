// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for 07b-unprotected-visibility (detector: default-visibility).
/// `_withdraw` was meant to be an internal helper; left `public` with no
/// access control, ANY caller can invoke it and drain the vault.
contract VisibilityVault {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    /// VULNERABLE: internal-intended state changer exposed as public.
    function _withdraw() public {
        (bool ok,) = payable(msg.sender).call{value: address(this).balance}("");
        require(ok);
    }
}
