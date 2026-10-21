// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 * Dataset: smartbugs/smartbugs-curated
 * Dataset path: dataset/short_addresses/short_address_example.sol
 * @source: https://ericrafaloff.com/analyzing-the-erc20-short-address-attack/
 * Original pragma: ^0.4.11
 * Original vulnerable line: 18  (function sendCoin(address to, uint amount) ...)
 * Report marker: <yes> <report> SHORT_ADDRESSES
 *
 * MIGRATION NOTES (0.4.11 -> 0.8.24):
 *   - pragma raised to ^0.8.24.
 *   - `uint` -> `uint256`, explicit visibility on getBalance, `constant` -> `view`.
 *   - `function MyToken()` -> `constructor()`.
 *   - `Transfer(...)` -> `emit Transfer(...)` (0.5+ requires the `emit` keyword).
 *   - Dataset contract name `MyToken` renamed to the required Pascal fixture
 *     name `ShortAddressExample`.
 *   - SEMANTICS-PRESERVING EDIT (deliberate, NOT a fix): the vulnerability lives
 *     in the *compiler-generated ABI decoder*. Solidity >= 0.5 validates calldata
 *     length before dispatching, so a 67-byte (under-length) calldata now reverts
 *     and the short-address bug would be masked. To restore the pre-0.5 decoder
 *     semantics (which silently zero-padded short calldata and therefore shifted
 *     the following argument), the two arguments are read manually from calldata
 *     at the canonical ABI head offsets (4 and 36) using inline assembly, exactly
 *     as the 0.4 decoder did. The body (balance check, debit, credit, event,
 *     return) is preserved verbatim and in its original order. This is NOT a fix.
 *   - No functions were added or removed.
 */
pragma solidity ^0.8.24;

contract ShortAddressExample {
    mapping(address => uint256) balances;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);

    constructor() {
        balances[tx.origin] = 10000;
    }

    // <yes> <report> SHORT_ADDRESSES
    function sendCoin() public returns (bool sufficient) {
        // --- restored 0.4 ABI decoder: read the two head words from raw calldata ---
        address to;
        uint256 amount;
        assembly {
            to := calldataload(4)
            amount := calldataload(36)
        }
        // --- original body, verbatim and in the original order ---
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
