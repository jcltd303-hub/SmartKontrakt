// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 26 (assembly SSTORE to a caller-chosen
/// slot). VULNERABLE BY DESIGN: set() lets anyone write any value to
/// any storage slot via assembly -- slot 0 is the owner.
contract AssemblyStore {
    address public owner; // slot 0

    constructor() {
        owner = msg.sender;
    }

    function set(uint256 slot, uint256 value) external {
        // BUG: arbitrary, unguarded storage write.
        assembly {
            sstore(slot, value)
        }
    }
}
