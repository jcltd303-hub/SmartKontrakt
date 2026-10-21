// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 * =========================================================================
 * Dataset:          smartbugs/smartbugs-curated
 * Dataset path:     dataset/reentrancy/etherstore.sol
 * Upstream source:  https://github.com/sigp/solidity-security-blog
 * Original author:  Suhabe Bugrara
 * Original pragma:  pragma solidity ^0.4.10;
 * Original vulnerable line: 27
 * Dataset report marker: // <yes> <report> REENTRANCY
 * =========================================================================
 *
 * This is the VULNERABLE port (contract EtherStore).
 *
 * Porting edits (0.4.10 -> 0.8.24 migration ONLY):
 *   - require(msg.sender.call.value(x)())  ->  (bool s,) = msg.sender.call{value: x}(""); require(s);
 *   - now  ->  block.timestamp
 *   - explicit uint256
 *   - `unchecked` around `balances[msg.sender] -= _weiToWithdraw`.
 *     Rationale: in 0.4.x that subtraction wrapped silently on underflow. ANY
 *     profitable re-entrant drain necessarily underflows it -- the inner frame
 *     decrements the balance first, then the outer frame decrements below zero.
 *     Solidity 0.8 checked arithmetic would revert there and MASK the bug, so
 *     `unchecked` is required to preserve the original 0.4 arithmetic semantics.
 *     (This is the only arithmetic edit; ordering is untouched.)
 *
 * THE VULNERABLE ORDERING IS PRESERVED VERBATIM: the external call on line 27
 * happens BEFORE `balances[msg.sender] -= _weiToWithdraw` and BEFORE the
 * lastWithdrawTime update, so a re-entrant withdrawFunds() still sees the old
 * balance and a stale lastWithdrawTime and passes every guard.
 */
pragma solidity ^0.8.24;

contract EtherStore {
    uint256 public withdrawalLimit = 1 ether;
    mapping(address => uint256) public lastWithdrawTime;
    mapping(address => uint256) public balances;

    function depositFunds() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds(uint256 _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);
        // limit the withdrawal
        require(_weiToWithdraw <= withdrawalLimit);
        // limit the time allowed to withdraw
        require(block.timestamp >= lastWithdrawTime[msg.sender] + 1 weeks);
        // <yes> <report> REENTRANCY
        (bool success, ) = msg.sender.call{value: _weiToWithdraw}("");
        require(success);
        unchecked {
            balances[msg.sender] -= _weiToWithdraw;
        }
        lastWithdrawTime[msg.sender] = block.timestamp;
    }
}
