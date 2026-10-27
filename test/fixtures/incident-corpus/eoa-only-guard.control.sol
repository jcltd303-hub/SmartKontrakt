// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract PotishSafe {
    uint256 public counter;
    // The EOA check guards no value flow, so it is a note, not a finding.
    function tick() external {
        require(tx.origin == msg.sender, "no contracts");
        counter += 1;
    }
}
