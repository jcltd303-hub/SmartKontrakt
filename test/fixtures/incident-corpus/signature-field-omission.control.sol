// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract GiddyishSafe {
    address public trusted;
    mapping(address => bool) public used;
    function claim(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, to, amount));
        require(ecrecover(digest, v, r, s) == trusted, "sig");
        require(!used[to], "used");
        used[to] = true;
        payable(to).transfer(amount);
    }
}
