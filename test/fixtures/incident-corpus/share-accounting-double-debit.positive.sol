// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// UNCX Vesting V2 shape: release and cancel both debit the global shares.
contract Vestingish {
    struct Pos { uint256 shares; }
    mapping(uint256 => Pos) public positions;
    uint256 public totalShares;
    function release(uint256 id) external {
        require(positions[id].shares > 0, "none");
        totalShares -= positions[id].shares;
        payable(msg.sender).transfer(positions[id].shares);
    }
    function cancel(uint256 id) external {
        require(positions[id].shares > 0, "none");
        totalShares -= positions[id].shares;
        payable(msg.sender).transfer(positions[id].shares);
    }
}
