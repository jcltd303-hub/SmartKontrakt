/*
 * PROVENANCE
 * -------------------------------------------------------------------
 * Dataset repo : smartbugs/smartbugs-curated
 * Dataset path : dataset/bad_randomness/guess_the_random_number.sol
 * Upstream @source: https://capturetheether.com/challenges/lotteries/guess-the-random-number/
 * Original pragma: ^0.4.21
 * Original vulnerable line(s): 15  (BAD_RANDOMNESS / SWC-120)
 * Port pragma  : ^0.8.24
 *
 * Migration edits (mechanical 0.4 -> 0.8 only):
 *   - `function GuessTheRandomNumberChallenge()` -> `constructor()`.
 *   - `keccak256(a, b)` -> `keccak256(abi.encodePacked(a, b))`.
 *   - `block.blockhash(x)` -> `blockhash(x)`.
 *   - `now` -> `block.timestamp`.
 *   - `msg.sender.transfer(x)` -> `payable(msg.sender).transfer(x)`.
 *
 * VULNERABILITY: the secret `answer` is derived purely from block variables
 * (`blockhash(block.number-1)` and `block.timestamp`) that are public and known
 * at (or before) the time of the guess, so an attacker can compute the answer.
 */
pragma solidity ^0.8.24;

contract GuessTheRandomNumber {
    uint8 answer;

    constructor() payable {
        require(msg.value == 1 ether);
        // <yes> <report> BAD_RANDOMNESS
        answer = uint8(uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), block.timestamp))));
    }

    function isComplete() public view returns (bool) {
        return address(this).balance == 0;
    }

    function guess(uint8 n) public payable {
        require(msg.value == 1 ether);

        if (n == answer) {
            payable(msg.sender).transfer(2 ether);
        }
    }
}
