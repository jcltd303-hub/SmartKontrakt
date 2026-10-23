// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 04 (ERC721 mint-callback reentrancy).
/// VULNERABLE BY DESIGN: mint() enforces a 1-per-wallet limit but
/// updates the minted counter only AFTER _safeMint fires
/// onERC721Received, so the recipient re-enters mint() and buys past
/// the limit in one payment flow.
contract NFTMinter {
    uint256 public constant PRICE = 0.1 ether;
    uint256 public nextId = 1;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public mintedCount;
    mapping(uint256 => address) public ownerOf;

    function mint() external payable {
        require(msg.value >= PRICE, "price not met");
        require(mintedCount[msg.sender] < 1, "limit: 1 per wallet");
        uint256 id = nextId++;
        ownerOf[id] = msg.sender;
        balanceOf[msg.sender] += 1;
        // Callback BEFORE the limit counter moves -- the bug.
        if (msg.sender.code.length > 0) {
            (bool ok, bytes memory ret) = msg.sender.call(
                abi.encodeWithSignature(
                    "onERC721Received(address,address,uint256,bytes)",
                    address(0),
                    address(0),
                    id,
                    bytes("")
                )
            );
            require(ok && ret.length == 32 && abi.decode(ret, (bytes4)) == bytes4(0x150b7a02), "receiver rejected");
        }
        mintedCount[msg.sender] += 1;
    }

    receive() external payable {}
}
