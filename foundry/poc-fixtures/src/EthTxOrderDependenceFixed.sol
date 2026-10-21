/*
 * PROVENANCE
 * -------------------------------------------------------------------
 * Dataset repo : smartbugs/smartbugs-curated
 * Dataset path : dataset/front_running/eth_tx_order_dependence_minimal.sol
 * Upstream @source: https://github.com/ConsenSys/evm-analyzer-benchmark-suite
 * Original pragma: ^0.4.16
 * Original vulnerable line(s): 23,31
 * Fixed variant: EthTxOrderDependenceFixed
 *
 * REMEDIATION (transaction order dependence): a commit-reveal scheme. A claimant
 * must first COMMIT a hash in an earlier block, then REVEAL it in a later block.
 * A front-run that merely reacts to a pending `setReward` in the same block can
 * therefore never win. `setReward` also no longer makes an ordering-dependent
 * immediate payout.
 *
 * NOTE: the fixed API changes `claimReward(uint256)` into
 * `claimReward(uint256,bytes32)` plus `commitClaim(bytes32)` - that is the point
 * of the remediation (you cannot remove ordering dependence while keeping a
 * single, order-reactive claim call).
 */
pragma solidity ^0.8.24;

contract EthTxOrderDependenceFixed {
    address public owner;
    bool public claimed;
    uint256 public reward;

    mapping(address => bytes32) public commitments;
    mapping(address => uint256) public commitBlock;

    constructor() {
        owner = msg.sender;
    }

    function setReward() public payable {
        require(!claimed);
        require(msg.sender == owner);
        // FIX: no ordering-dependent immediate payout.
        reward = msg.value;
    }

    // FIX: step 1 - commit to the claim in one block ...
    function commitClaim(bytes32 h) public {
        require(!claimed);
        require(commitments[msg.sender] == bytes32(0), "already committed");
        commitments[msg.sender] = h;
        commitBlock[msg.sender] = block.number;
    }

    // FIX: step 2 - reveal in a strictly later block.
    function claimReward(uint256 submission, bytes32 secret) public {
        require(!claimed);
        require(submission < 10);
        require(commitments[msg.sender] != bytes32(0), "no commitment");
        require(commitBlock[msg.sender] < block.number, "commit and reveal must be in separate blocks");
        require(commitments[msg.sender] == keccak256(abi.encodePacked(submission, secret)), "bad reveal");
        payable(msg.sender).transfer(reward);
        claimed = true;
    }
}
