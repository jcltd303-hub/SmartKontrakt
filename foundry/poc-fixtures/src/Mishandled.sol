// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 * Dataset: smartbugs/smartbugs-curated
 * Dataset path: dataset/unchecked_low_level_calls/mishandled.sol
 * @source: https://github.com/seresistvanandras/EthBench/blob/master/Benchmark/Simple/mishandled.sol
 * Original pragma: ^0.4.0
 * Original vulnerable line: 14  (msg.sender.send(amountToWithdraw);)
 * Report marker: <yes> <report> UNCHECKED_LL_CALLS
 *
 * MIGRATION NOTES (0.4.0 -> 0.8.24):
 *   - pragma raised to ^0.8.24.
 *   - `uint` -> `uint256`, explicit `public` visibility added on withdrawBalance.
 *   - `msg.sender.send(x)` -> `payable(msg.sender).send(x)`: since 0.8.0
 *     msg.sender has type `address` (not `address payable`), so the explicit
 *     `payable(...)` cast is required. `.send` (2300-gas stipend, returns bool)
 *     is preserved on purpose -- the bug is precisely the unchecked return value.
 *   - Dataset contract name `SendBack` renamed to the required Pascal fixture
 *     name `Mishandled`.
 *   - No functions were added or removed.
 */
pragma solidity ^0.8.24;

contract Mishandled {
    mapping(address => uint256) userBalances;

    function withdrawBalance() public {
        uint256 amountToWithdraw = userBalances[msg.sender];
        userBalances[msg.sender] = 0;
        // <yes> <report> UNCHECKED_LL_CALLS
        payable(msg.sender).send(amountToWithdraw);
    }
}
