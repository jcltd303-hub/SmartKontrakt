// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 11 (uninitialized implementation behind a
/// proxy). The implementation's initialize() is unguarded AND the
/// implementation itself was never initialized, so anyone can
/// initialize the implementation directly and own it.
contract UninitializedImpl {
    address public owner; // slot 0
    bool public initialized;

    function initialize(address newOwner) external {
        // BUG: no initializer guard on the implementation itself.
        owner = newOwner;
        initialized = true;
    }

    function version() external pure returns (uint256) {
        return 1;
    }
}

/// Minimal EIP-1967 proxy: implementation address lives in the
/// standard slot; every call delegatecalls to it.
contract Eip1967Proxy {
    bytes32 internal constant IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address impl) {
        bytes32 slot = IMPL_SLOT;
        assembly {
            sstore(slot, impl)
        }
    }

    fallback() external payable {
        bytes32 slot = IMPL_SLOT;
        assembly {
            let impl := sload(slot)
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
