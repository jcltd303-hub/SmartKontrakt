// SPDX-License-Identifier: MIT
/*
 * FIXED VARIANT of dataset/short_addresses/short_address_example.sol
 * (smartbugs/smartbugs-curated)
 *
 * Standard remediation: validate that the calldata is well-formed (i.e. that the
 * address argument is fully padded to its canonical 32-byte head word) before
 * reading the arguments. Under-length calldata -- the vector that shifts the
 * following `amount` argument -- is rejected. This is exactly the validation the
 * Solidity >= 0.5 ABI decoder performs automatically.
 *
 * Mechanical migration: `Transfer(...)` -> `emit Transfer(...)` (0.5+ keyword).
 */
pragma solidity ^0.8.24;

contract ShortAddressExampleFixed {
    mapping(address => uint256) balances;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);

    constructor() {
        balances[tx.origin] = 10000;
    }

    // <yes> <report> SHORT_ADDRESSES
    function sendCoin() public returns (bool sufficient) {
        // remediation: reject malformed (under/over-padded) calldata
        require(msg.data.length == 68, "malformed calldata");
        address to;
        uint256 amount;
        assembly {
            to := calldataload(4)
            amount := calldataload(36)
        }
        if (balances[msg.sender] < amount) return false;
        balances[msg.sender] -= amount;
        balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function getBalance(address addr) public view returns (uint256) {
        return balances[addr];
    }
}
