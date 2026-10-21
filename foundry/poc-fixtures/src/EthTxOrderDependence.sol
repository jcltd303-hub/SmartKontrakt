/*
 * PROVENANCE
 * -------------------------------------------------------------------
 * Dataset repo : smartbugs/smartbugs-curated
 * Dataset path : dataset/front_running/eth_tx_order_dependence_minimal.sol
 * Upstream @source: https://github.com/ConsenSys/evm-analyzer-benchmark-suite
 * Original pragma: ^0.4.16
 * Original vulnerable line(s): 23,31  (FRONT_RUNNING / SWC-114)
 * Port pragma  : ^0.8.24
 *
 * Migration edits (mechanical 0.4 -> 0.8 only):
 *   - `function EthTxOrderDependenceMinimal()` -> `constructor()`.
 *   - `uint` -> `uint256`; explicit visibility.
 *   - `owner.transfer(x)` / `msg.sender.transfer(x)` -> `payable(...).transfer(x)`.
 * The ordering-dependent payout is preserved verbatim.
 *
 * VULNERABILITY (transaction order dependence): `claimReward` pays out the
 * current `reward` to whoever calls it first (submission < 10). An attacker who
 * sees the owner's pending `setReward` can front-run it with `claimReward`,
 * stealing the reward and setting `claimed = true`, which permanently blocks the
 * owner's deposit.
 */
pragma solidity ^0.8.24;

contract EthTxOrderDependence {
    address public owner;
    bool public claimed;
    uint256 public reward;

    constructor() {
        owner = msg.sender;
    }

    function setReward() public payable {
        require (!claimed);

        require(msg.sender == owner);
        // <yes> <report> FRONT_RUNNING
        payable(owner).transfer(reward);
        reward = msg.value;
    }

    function claimReward(uint256 submission) public {
        require (!claimed);
        require(submission < 10);
        // <yes> <report> FRONT_RUNNING
        payable(msg.sender).transfer(reward);
        claimed = true;
    }
}
