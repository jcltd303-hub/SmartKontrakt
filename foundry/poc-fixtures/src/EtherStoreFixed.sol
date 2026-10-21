// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 * =========================================================================
 * Dataset:          smartbugs/smartbugs-curated
 * Dataset path:     dataset/reentrancy/etherstore.sol
 * Upstream source:  https://github.com/sigp/solidity-security-blog
 * Original pragma:  pragma solidity ^0.4.10;
 * Original vulnerable line: 27
 * =========================================================================
 *
 * FIXED variant (contract EtherStoreFixed).
 *
 * Remediation: checks-effects-interactions. `balances[msg.sender]` is decremented
 * and `lastWithdrawTime[msg.sender]` is set BEFORE the external call. A
 * re-entrant withdrawFunds() then sees a zeroed balance (and a fresh
 * lastWithdrawTime) and reverts on its own guards, so it cannot pull a second
 * time. Because the decrement now happens only once, no `unchecked` is needed.
 */
pragma solidity ^0.8.24;

contract EtherStoreFixed {
    uint256 public withdrawalLimit = 1 ether;
    mapping(address => uint256) public lastWithdrawTime;
    mapping(address => uint256) public balances;

    function depositFunds() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds(uint256 _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);
        require(_weiToWithdraw <= withdrawalLimit);
        require(block.timestamp >= lastWithdrawTime[msg.sender] + 1 weeks);
        balances[msg.sender] -= _weiToWithdraw;      // EFFECT before INTERACTION (fix)
        lastWithdrawTime[msg.sender] = block.timestamp;
        (bool success, ) = msg.sender.call{value: _weiToWithdraw}("");
        require(success);
    }
}
