// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 34 ("private" secret readable on-chain).
/// VULNERABLE BY DESIGN: a secret sits in a `private` variable at slot
/// 0. `private` only hides it from other contracts -- any node reader
/// can pull it straight from storage with eth_getStorageAt / vm.load.
contract PrivateSecret {
    // slot 0 -- keccak256("the eagle flies at midnight"), stored "privately".
    bytes32 private _secret;

    constructor() {
        _secret = keccak256("the eagle flies at midnight");
    }

    function checkSecret(bytes32 guess) external view returns (bool) {
        return guess == _secret;
    }
}
