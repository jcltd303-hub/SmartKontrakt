// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 40 (ERC4626 first-depositor inflation).
/// A minimal shares-for-assets vault with NO virtual offset and NO
/// dead-share protection: shares = assets * supply / balance, priced
/// off the vault's live token balance, so a donation moves the price.
contract MockAsset40 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "allowance");
        require(balanceOf[from] >= amount, "insufficient");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract InflationVault {
    MockAsset40 public assetToken;
    mapping(address => uint256) public balanceOf; // shares
    uint256 public totalSupply; // shares

    constructor(address asset_) {
        assetToken = MockAsset40(asset_);
    }

    function asset() external view returns (address) {
        return address(assetToken);
    }

    function totalAssets() public view returns (uint256) {
        return assetToken.balanceOf(address(this));
    }

    function previewDeposit(uint256 assets) public view returns (uint256) {
        if (totalSupply == 0) return assets;
        // BUG: no virtual offset -- donation inflates the denominator.
        return (assets * totalSupply) / totalAssets();
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = previewDeposit(assets);
        require(assetToken.transferFrom(msg.sender, address(this), assets), "pull failed");
        balanceOf[receiver] += shares;
        totalSupply += shares;
    }
}
