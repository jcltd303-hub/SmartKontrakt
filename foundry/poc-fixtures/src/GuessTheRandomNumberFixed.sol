/*
 * PROVENANCE
 * -------------------------------------------------------------------
 * Dataset repo : smartbugs/smartbugs-curated
 * Dataset path : dataset/bad_randomness/guess_the_random_number.sol
 * Upstream @source: https://capturetheether.com/challenges/lotteries/guess-the-random-number/
 * Original pragma: ^0.4.21
 * Original vulnerable line(s): 15
 * Fixed variant: GuessTheRandomNumberFixed
 *
 * REMEDIATION (bad randomness): the winning number is supplied by a trusted
 * external oracle instead of being derived from public block variables, so the
 * block-derived "attack" value no longer matches the secret.
 */
pragma solidity ^0.8.24;

// Minimal external randomness oracle (the trusted off-chain source).
contract GuessTheRandomNumberOracle {
    uint8 public value;
    function setValue(uint8 v) external { value = v; }
    function random() external view returns (uint8) { return value; }
}

contract GuessTheRandomNumberFixed {
    uint8 private answer;
    GuessTheRandomNumberOracle public oracle;

    constructor(address _oracle) payable {
        require(msg.value == 1 ether);
        oracle = GuessTheRandomNumberOracle(_oracle);
    }

    function isComplete() public view returns (bool) {
        return address(this).balance == 0;
    }

    function guess(uint8 n) public payable {
        require(msg.value == 1 ether);
        // FIX: the secret comes from an external oracle, not from block variables.
        uint8 secret = oracle.random();
        if (n == secret) {
            payable(msg.sender).transfer(2 ether);
        }
    }
}
