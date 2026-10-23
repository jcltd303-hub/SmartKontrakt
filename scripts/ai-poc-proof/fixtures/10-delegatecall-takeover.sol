// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 10 (delegatecall to caller-chosen logic).
/// VULNERABLE BY DESIGN: execute() delegatecalls ANY target with ANY
/// calldata, with no access check -- the callee's code runs in this
/// contract's storage and overwrites slot 0 (owner).
contract DelegatecallBox {
    address public owner; // slot 0

    constructor() {
        owner = msg.sender;
    }

    function execute(address impl, bytes calldata data) external {
        // BUG: unguarded delegatecall to a caller-chosen implementation.
        (bool ok, ) = impl.delegatecall(data);
        require(ok, "delegatecall failed");
    }

    function migrate(address impl, bytes calldata data) external {
        // BUG: a second unguarded delegatecall entry point (migration
        // hook) with the same flaw.
        (bool ok, ) = impl.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
