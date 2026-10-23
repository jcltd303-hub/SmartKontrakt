// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for 44-external-contract-ref (detector:
/// external-contract-referencing). The payout destination is an external
/// contract reference ANYONE can swap; `withdraw` then routes the whole
/// balance through whatever contract the reference points at.
contract ExternalRefVault {
    address public target;

    receive() external payable {}

    /// VULNERABLE: unguarded setter for the external reference.
    function setTarget(address t) public {
        target = t;
    }

    /// Routes the balance through the (attacker-controlled) reference.
    function withdraw() public {
        (bool ok,) = payable(target).call{value: address(this).balance}("");
        require(ok);
    }
}
