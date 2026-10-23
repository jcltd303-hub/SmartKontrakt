// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 03 (ERC777 hook reentrancy).
/// Mock777 is a minimal ERC777-style token: send() invokes the
/// recipient's tokensReceived() hook. Its transferFrom is intentionally
/// lenient (mock) so the fixture needs no allowance choreography; the
/// VULNERABLE side is the vault, which sends tokens back before
/// debiting the caller's ledger.
contract Mock777 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "insufficient");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function send(address to, uint256 amount, bytes calldata) external {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        if (to.code.length > 0) {
            (bool ok, ) = to.call(
                abi.encodeWithSignature(
                    "tokensReceived(address,address,address,uint256,bytes,bytes)",
                    msg.sender,
                    msg.sender,
                    to,
                    amount,
                    bytes(""),
                    bytes("")
                )
            );
            ok; // hook result ignored, like real ERC777 senders
        }
    }
}

contract ERC777Vault {
    Mock777 public token;
    mapping(address => uint256) public deposits;

    constructor(address token_) {
        token = Mock777(token_);
    }

    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "pull failed");
        deposits[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient deposit");
        // BUG: tokens sent (hook fires) before the ledger is debited;
        // the debit is unchecked, the classic wrap preserved on purpose.
        token.send(msg.sender, amount, bytes(""));
        unchecked {
            deposits[msg.sender] -= amount;
        }
    }
}
