// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 35 (generic flash loan round-trip).
/// A minimal Aave-v3-shaped pool: flashLoanSimple moves the asset to the
/// borrower, invokes executeOperation, then pulls amount + premium
/// back. Premium is 0 in this fixture so the round-trip is exact; the
/// primitive being proven is uncollateralized borrow-use-repay in ONE
/// transaction.
contract MockAsset35 {
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

interface IFlashBorrower35 {
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

contract FlashPool {
    function flashLoanSimple(
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16
    ) external {
        MockAsset35 token = MockAsset35(asset);
        uint256 premium = 0;
        require(token.transfer(msg.sender, amount), "lend failed");
        bool ok = IFlashBorrower35(msg.sender).executeOperation(
            asset,
            amount,
            premium,
            msg.sender,
            params
        );
        require(ok, "callback failed");
        require(
            token.transferFrom(msg.sender, address(this), amount + premium),
            "repay failed"
        );
    }
}
