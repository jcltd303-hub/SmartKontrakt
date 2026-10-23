// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 * =========================================================================
 * Modelled:         no dataset source — this port is NOT a SmartBugs
 *                   Curated contract and claims no dataset path.
 * Modelled on:      fallback template foundry/poc-fallbacks/46-token-rescue.t.sol
 *                   (index.json provenance: "modelled"), whose pattern is
 *                   the widely deployed unauthenticated-rescue token
 *                   shape — proven end-to-end against a live instance
 *                   (the FUUU token) by the SmartKontrakt C+D+E batch:
 *                   rescueETH(uint256) / rescueERC20(address,uint256)
 *                   callable by ANY account, sending the contract's
 *                   funds to a FIXED wallet baked into the contract.
 * =========================================================================
 *
 * This is the VULNERABLE port (contract TokenRescue).
 *
 * THE VULNERABILITY IS PRESERVED VERBATIM IN SHAPE: rescueETH and
 * rescueERC20 carry NO access check. The recipient is fixed (nobody
 * profits from calling them unless they are the fixed wallet), which
 * is exactly why the pattern survives audits — it reads as a harmless
 * housekeeping helper. It is not: any arbitrary caller can force the
 * drain at a moment of their choosing (griefing / timing attacks /
 * laundering the move through an unrelated account), and the funds
 * leave the contract's control permanently.
 */
pragma solidity ^0.8.24;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

contract TokenRescue {
    string public constant name = "Rescue Token";
    string public constant symbol = "RSC";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    /// The fixed rescue recipient, baked in like the pattern in the
    /// wild (a "devWallet"). Rescue functions send HERE — never to the
    /// caller — which is the detail that makes the missing access
    /// check look harmless.
    address public constant DEV_WALLET = address(0xD3AD);

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    constructor(uint256 supply) {
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

    /// VULNERABLE: no access check. Anyone can force the contract's
    /// entire ETH balance to the fixed wallet at any time.
    function rescueETH(uint256 amount) external {
        (bool ok, ) = DEV_WALLET.call{value: amount}("");
        require(ok, "rescueETH failed");
    }

    /// VULNERABLE: no access check. Anyone can force tokens the
    /// contract holds (including its own token) to the fixed wallet.
    function rescueERC20(address token, uint256 amount) external {
        if (token == address(this)) {
            _transfer(address(this), DEV_WALLET, amount);
        } else {
            require(IERC20Like(token).transfer(DEV_WALLET, amount), "rescueERC20 failed");
        }
    }

    receive() external payable {}
}
