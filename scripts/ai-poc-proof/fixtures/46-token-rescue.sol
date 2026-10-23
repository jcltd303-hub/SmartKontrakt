// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 46 (token rescue / token drain).
/// VULNERABLE BY DESIGN: rescueERC20 has no access check -- anyone can
/// move the contract's whole ERC-20 balance out (to a fixed dev wallet,
/// the FUUU field pattern). The contract is its own token and holds a
/// balance of itself, which is the case template 46 judges by default
/// (POC_TOKEN unset).
contract RescueToken {
    string public name = "Rescue Token";
    string public symbol = "RSC";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    // The FUUU field case's dev wallet (checksummed spelling, as
    // address literals require).
    address public devWallet = 0x49579F18fc47B294B86bfb10d0385106183E9A1C;

    mapping(address => uint256) public balanceOf;

    constructor() {
        totalSupply = 1_000_000 ether;
        balanceOf[address(this)] = totalSupply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    /// No access check: any caller can rescue the entire balance.
    function rescueERC20(address token, uint256 amount) external {
        require(token == address(this), "only own token in this fixture");
        require(balanceOf[address(this)] >= amount, "balance");
        balanceOf[address(this)] -= amount;
        balanceOf[devWallet] += amount;
    }
}
