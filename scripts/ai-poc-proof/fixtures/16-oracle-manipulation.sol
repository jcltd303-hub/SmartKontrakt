// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 16 (spot-price / balance-as-price oracle).
/// A minimal constant-product AMM stands in for the DEX. The victim
/// oracle reads the pair's SPOT reserves (getPrice) and its own token
/// balance (exchangeRate) -- both manipulable in one transaction.
contract MockToken16 {
    string public name;
    string public symbol;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory name_, string memory symbol_) {
        name = name_;
        symbol = symbol_;
    }

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

contract MiniPair {
    MockToken16 public tokenA;
    MockToken16 public tokenB;

    constructor(address a, address b) {
        tokenA = MockToken16(a);
        tokenB = MockToken16(b);
    }

    function getReserves() public view returns (uint256 ra, uint256 rb) {
        return (tokenA.balanceOf(address(this)), tokenB.balanceOf(address(this)));
    }

    /// Swap priced off SPOT balances. Called by the router only, AFTER
    /// the router pulled amountIn in -- so the in-side denominator is
    /// the current (post-pull) in-balance.
    function swap(address tokenIn, uint256 amountIn, address to) external returns (uint256 out) {
        (uint256 ra, uint256 rb) = getReserves();
        if (tokenIn == address(tokenA)) {
            out = (amountIn * rb) / ra;
            require(tokenB.transfer(to, out), "out failed");
        } else {
            out = (amountIn * ra) / rb;
            require(tokenA.transfer(to, out), "out failed");
        }
    }
}

contract MiniRouter {
    MiniPair public pair;

    constructor(address pair_) {
        pair = MiniPair(pair_);
    }

    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256,
        address[] calldata path,
        address to,
        uint256
    ) external returns (uint256[] memory amounts) {
        MockToken16 tokenIn = MockToken16(path[0]);
        require(tokenIn.transferFrom(msg.sender, address(pair), amountIn), "pull failed");
        uint256 out = pair.swap(path[0], amountIn, to);
        amounts = new uint256[](2);
        amounts[0] = amountIn;
        amounts[1] = out;
    }
}

/// The vulnerable consumer: prices straight off spot state.
contract SpotOracle {
    MiniPair public pair;
    MockToken16 public tokenB;

    constructor(address pair_, address tokenB_) {
        pair = MiniPair(pair_);
        tokenB = MockToken16(tokenB_);
    }

    /// Spot price from live reserves -- one swap moves it.
    function getPrice() external view returns (uint256) {
        (uint256 ra, uint256 rb) = pair.getReserves();
        require(ra > 0, "no liquidity");
        return (rb * 1e18) / ra;
    }

    /// Balance-as-price: the contract's own token balance IS the input.
    function exchangeRate() external view returns (uint256) {
        return tokenB.balanceOf(address(this)) + 1;
    }
}
