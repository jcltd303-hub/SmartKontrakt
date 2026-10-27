// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// BlockChainCasino shape: settle a win, refund a loss after the timeout.
contract Casinoish {
    struct Bet { address player; uint256 stake; uint256 commit; }
    mapping(uint256 => Bet) public bets;
    uint256 public constant BET_EXPIRATION_BLOCKS = 250;
    uint256 public bankroll;
    function placeBet(uint256 id, uint256 commit) external payable {
        bets[id] = Bet(msg.sender, msg.value, commit);
        bankroll += msg.value;
    }
    function settleBet(uint256 id, bytes32 reveal, bytes32 blockHash) external {
        Bet storage b = bets[id];
        require(uint256(keccak256(abi.encode(reveal))) == b.commit, "bad reveal");
        uint256 payout = b.stake * 2;
        delete bets[id];
        payable(b.player).transfer(payout);
    }
    function refundBet(uint256 id) external {
        Bet storage b = bets[id];
        require(block.number > b.commit + BET_EXPIRATION_BLOCKS, "too early");
        uint256 stake = b.stake;
        delete bets[id];
        payable(b.player).transfer(stake);
    }
}
