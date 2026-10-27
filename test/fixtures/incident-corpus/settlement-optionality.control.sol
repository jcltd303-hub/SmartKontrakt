// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract CasinoishSafe {
    struct Bet { address player; uint256 stake; uint256 commit; }
    mapping(uint256 => Bet) public bets;
    address public house;
    uint256 public constant BET_EXPIRATION_BLOCKS = 250;
    modifier onlyHouse() {
        require(msg.sender == house, "house");
        _;
    }
    function placeBet(uint256 id, uint256 commit) external payable {
        bets[id] = Bet(msg.sender, msg.value, commit);
    }
    // The house can force settlement, so the option is not free.
    function settleBet(uint256 id, bytes32 reveal) external onlyHouse {
        Bet storage b = bets[id];
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
