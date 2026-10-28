pragma solidity ^0.4.24;

// Minimal game contract for the BlockChainCasino partition demo.
// The casino calls game(betMask, modulo, entropy, betAmount) during settle and
// getMaxWin(betMask, modulo, betAmount) during place. Both must exist and return
// sane values or placeBet reverts inside checkBetAmounts.
contract MockGame {
    // Deterministic and boring: a bet wins only if entropy's low byte is even, and
    // the payout is 2x the net stake.
    function game(uint betMask, uint8 modulo, bytes32 entropy, uint betAmount)
        public
        pure
        returns (uint winAmount, uint256[10] result)
    {
        uint roll = uint(entropy) % modulo;
        // betMask is treated as "win if roll < mask"
        winAmount = roll < betMask ? betAmount * 2 : 0;
        for (uint i = 0; i < 10; i++) {
            result[i] = roll;
        }
    }

    function getMaxWin(uint betMask, uint8 modulo, uint betAmount)
        public
        pure
        returns (uint maxWin)
    {
        // Worst case for the house is the full 2x payout.
        maxWin = betMask > 0 ? betAmount * 2 : 0;
    }
}
