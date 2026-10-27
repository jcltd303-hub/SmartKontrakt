// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract RouletteishFixed {
    address public constant GAME = 0x2222222222222222222222222222222222222222;
    function spin(uint256 entropy) external payable {
        (bool ok, bytes memory result) = GAME.call{value: msg.value}(
            abi.encodeWithSignature("play(uint256)", entropy)
        );
        require(ok, "game failed");
        bool won = abi.decode(result, (bool));
        if (won) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }
}
