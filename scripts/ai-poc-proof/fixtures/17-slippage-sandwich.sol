// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 17 (zero-slippage sandwich).
/// Same minimal AMM shape as type 16 (standalone copy). The VULNERABLE
/// side is VictimSwapper: it swaps through the router with
/// amountOutMin == 0, so a frontrun moves the price against it and
/// the backrun pockets the difference.
contract MockToken17 {
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

contract MiniPair17 {
    MockToken17 public tokenA;
    MockToken17 public tokenB;

    constructor(address a, address b) {
        tokenA = MockToken17(a);
        tokenB = MockToken17(b);
    }

    function getReserves() public view returns (uint256 ra, uint256 rb) {
        return (tokenA.balanceOf(address(this)), tokenB.balanceOf(address(this)));
    }

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

contract MiniRouter17 {
    MiniPair17 public pair;

    constructor(address pair_) {
        pair = MiniPair17(pair_);
    }

    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256,
        address[] calldata path,
        address to,
        uint256
    ) external returns (uint256[] memory amounts) {
        MockToken17 tokenIn = MockToken17(path[0]);
        require(tokenIn.transferFrom(msg.sender, address(pair), amountIn), "pull failed");
        uint256 out = pair.swap(path[0], amountIn, to);
        amounts = new uint256[](2);
        amounts[0] = amountIn;
        amounts[1] = out;
    }
}

/// The victim flow: swaps its own TOKEN_IN with ZERO slippage protection.
contract VictimSwapper {
    MiniRouter17 public router;
    MockToken17 public tokenIn;
    MockToken17 public tokenOut;

    constructor(address router_, address in_, address out_) {
        router = MiniRouter17(router_);
        tokenIn = MockToken17(in_);
        tokenOut = MockToken17(out_);
    }

    function swap(uint256 amount) external {
        tokenIn.approve(address(router), amount);
        address[] memory path = new address[](2);
        path[0] = address(tokenIn);
        path[1] = address(tokenOut);
        // BUG: amountOutMin = 0 -- any price is accepted.
        router.swapExactTokensForTokens(amount, 0, path, address(this), block.timestamp + 300);
    }
}
