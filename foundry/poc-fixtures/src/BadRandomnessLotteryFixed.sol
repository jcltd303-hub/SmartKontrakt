/*
 * PROVENANCE
 * -------------------------------------------------------------------
 * Dataset repo : smartbugs/smartbugs-curated
 * Dataset path : dataset/bad_randomness/lottery.sol
 * Upstream @source: https://etherscan.io/address/0x80ddae5251047d6ceb29765f38fed1c0013004b7#code
 * Original pragma: ^0.4.0
 * Original vulnerable line(s): 38,42
 * Fixed variant: BadRandomnessLotteryFixed
 *
 * REMEDIATION (bad randomness): the win condition comes from a trusted external
 * oracle, not from `block.number` parity, so a bettor can no longer force a win
 * by choosing the block they bet in.
 */
pragma solidity ^0.8.24;

contract BadRandomnessLotteryOracle {
    bool public value;
    function setValue(bool v) external { value = v; }
    function randomBool() external view returns (bool) { return value; }
}

contract BadRandomnessLotteryFixed {
    event GetBet(uint256 betAmount, uint256 blockNumber, bool won);

    struct Bet {
        uint256 betAmount;
        uint256 blockNumber;
        bool won;
    }

    address private organizer;
    Bet[] private bets;
    BadRandomnessLotteryOracle public oracle;

    constructor(address _oracle) {
        organizer = msg.sender;
        oracle = BadRandomnessLotteryOracle(_oracle);
    }

    receive() external payable {
        revert();
    }

    function makeBet() public payable {
        // FIX: outcome from an external oracle, not block-number parity.
        bool won = oracle.randomBool();

        bets.push(Bet(msg.value, block.number, won));

        if(won) {
            if(!payable(msg.sender).send(msg.value)) {
                revert();
            }
        }
    }

    function getBets() public {
        if(msg.sender != organizer) { revert(); }

        for (uint256 i = 0; i < bets.length; i++) {
            emit GetBet(bets[i].betAmount, bets[i].blockNumber, bets[i].won);
        }
    }

    function destroy() public {
        if(msg.sender != organizer) { revert(); }

        selfdestruct(payable(organizer));
    }
}
