/*
 * PROVENANCE
 * -------------------------------------------------------------------
 * Dataset repo : smartbugs/smartbugs-curated
 * Dataset path : dataset/bad_randomness/lottery.sol
 * Upstream @source: https://etherscan.io/address/0x80ddae5251047d6ceb29765f38fed1c0013004b7#code
 * Original pragma: ^0.4.0
 * Original vulnerable line(s): 38,42  (BAD_RANDOMNESS / SWC-120)
 * Port pragma  : ^0.8.24
 *
 * Migration edits (mechanical 0.4 -> 0.8 only):
 *   - `function Lottery()` -> `constructor()`; explicit visibility.
 *   - fallback `function() { throw; }` -> `receive() external payable { revert(); }`.
 *   - `throw` -> `revert()`.
 *   - `msg.sender.send(x)` -> `payable(msg.sender).send(x)`.
 *   - `suicide` -> `selfdestruct`.
 *
 * VULNERABILITY: the win condition is `block.number % 2 == 0` - a value the
 * bettor controls by choosing which block to bet in, so a win is deterministic.
 */
pragma solidity ^0.8.24;

contract BadRandomnessLottery {
    event GetBet(uint256 betAmount, uint256 blockNumber, bool won);

    struct Bet {
        uint256 betAmount;
        uint256 blockNumber;
        bool won;
    }

    address private organizer;
    Bet[] private bets;

    // Create a new lottery with numOfBets supported bets.
    constructor() {
        organizer = msg.sender;
    }

    // Fallback function returns ether
    receive() external payable {
        revert();
    }

    // Make a bet
    function makeBet() public payable {
        // Won if block number is even
        // (note: this is a terrible source of randomness, please don't use this with real money)
        // <yes> <report> BAD_RANDOMNESS
        bool won = (block.number % 2) == 0;

        // Record the bet with an event
        // <yes> <report> BAD_RANDOMNESS
        bets.push(Bet(msg.value, block.number, won));

        // Payout if the user won, otherwise take their money
        if(won) {
            if(!payable(msg.sender).send(msg.value)) {
                // Return ether to sender
                revert();
            }
        }
    }

    // Get all bets that have been made
    function getBets() public {
        if(msg.sender != organizer) { revert(); }

        for (uint256 i = 0; i < bets.length; i++) {
            emit GetBet(bets[i].betAmount, bets[i].blockNumber, bets[i].won);
        }
    }

    // Suicide :(
    function destroy() public {
        if(msg.sender != organizer) { revert(); }

        selfdestruct(payable(organizer));
    }
}
