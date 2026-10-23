// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 * =========================================================================
 * Modelled:         no dataset source — see TokenRescue.sol. Same
 *                   modelled pattern (fallback template
 *                   foundry/poc-fallbacks/46-token-rescue.t.sol).
 * =========================================================================
 *
 * FIXED variant (contract TokenRescueFixed).
 *
 * Remediation: the rescue functions are owner-gated. The recipient
 * stays the fixed wallet — the fix is purely the missing access
 * check, which is the whole vulnerability: with the gate, the rescue
 * path is the deployer's housekeeping tool it appeared to be; an
 * arbitrary caller can no longer force the drain.
 */
pragma solidity ^0.8.24;

interface IERC20LikeFixed {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

contract TokenRescueFixed {
    string public constant name = "Rescue Token";
    string public constant symbol = "RSC";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    address public constant DEV_WALLET = address(0xD3AD);
    address public owner;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(uint256 supply) {
        owner = msg.sender;
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }

    /// FIXED: owner-gated — an arbitrary caller reverts.
    function rescueETH(uint256 amount) external onlyOwner {
        (bool ok, ) = DEV_WALLET.call{value: amount}("");
        require(ok, "rescueETH failed");
    }

    /// FIXED: owner-gated — an arbitrary caller reverts.
    function rescueERC20(address token, uint256 amount) external onlyOwner {
        if (token == address(this)) {
            _transfer(address(this), DEV_WALLET, amount);
        } else {
            require(IERC20LikeFixed(token).transfer(DEV_WALLET, amount), "rescueERC20 failed");
        }
    }

    receive() external payable {}
}
