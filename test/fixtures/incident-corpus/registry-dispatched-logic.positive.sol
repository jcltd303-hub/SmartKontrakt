// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// CoinAndRoulette shape: the win rule lives in a registry-supplied contract.
contract Rouletteish {
    mapping(uint256 => address) public gameAddress;
    function spin(uint256 gameId, uint256 entropy) external payable {
        address game = gameAddress[gameId];
        (bool ok, bytes memory result) = game.call{value: msg.value}(
            abi.encodeWithSignature("play(uint256)", entropy)
        );
        require(ok, "game failed");
        bool won = abi.decode(result, (bool));
        if (won) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }
}
