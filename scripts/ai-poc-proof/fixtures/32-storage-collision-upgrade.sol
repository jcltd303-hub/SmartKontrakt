// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 32 (storage collision via unguarded
/// upgrade). A hand-rolled proxy: slot 0 is owner, slot 1 is the
/// implementation. VULNERABLE BY DESIGN: upgradeTo() has no access
/// check, so anyone can point the proxy at their own implementation
/// and run its code against the proxy's storage -- slot 0 included.
contract CollisionProxy {
    address public owner; // slot 0
    address public implementation; // slot 1

    constructor(address impl) {
        owner = msg.sender;
        implementation = impl;
    }

    function upgradeTo(address impl) external {
        // BUG: unguarded upgrade.
        implementation = impl;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

/// Benign initial implementation.
contract ImplV1_32 {
    function version() external pure returns (uint256) {
        return 1;
    }
}
