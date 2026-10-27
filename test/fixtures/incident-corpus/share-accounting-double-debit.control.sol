// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract VestingishSafe {
    struct Pos { uint256 shares; }
    mapping(uint256 => Pos) public positions;
    uint256 public totalShares;
    function release(uint256 id) external {
        uint256 s = positions[id].shares;
        require(s > 0, "none");
        positions[id].shares = 0;
        totalShares -= s;
        payable(msg.sender).transfer(s);
    }
    function cancel(uint256 id) external {
        uint256 s = positions[id].shares;
        require(s > 0, "none");
        positions[id].shares = 0;
        totalShares -= s;
        payable(msg.sender).transfer(s);
    }
}
