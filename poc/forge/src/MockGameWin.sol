pragma solidity ^0.4.24;

// Deterministic game for the refund-only PoC: the bet ALWAYS wins and pays 2x the
// net stake. The point of the demo is the difference between settling and refunding,
// not the roll, so the outcome must not depend on a blockhash nobody can predict
// before placement.
contract MockGameWin {
    function game(uint betMask, uint8 modulo, bytes32 entropy, uint betAmount)
        public
        pure
        returns (uint winAmount, uint256[10] result)
    {
        winAmount = betAmount * 2;
        for (uint i = 0; i < 10; i++) result[i] = 0;
    }

    function getMaxWin(uint betMask, uint8 modulo, uint betAmount)
        public
        pure
        returns (uint maxWin)
    {
        maxWin = betAmount * 2;
    }
}
