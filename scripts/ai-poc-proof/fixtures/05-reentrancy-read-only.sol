// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 05 (read-only reentrancy).
/// Same vulnerable shape as 01, plus the balanceOf() view the class is
/// about: during the withdraw callback the view still reports the
/// pre-withdraw balance, so any reader pricing off it acts on stale
/// data.
contract ReadOnlyVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        // BUG: the view reads this mapping, updated only after the call.
        balances[msg.sender] = 0;
    }

    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }

    receive() external payable {}
}
