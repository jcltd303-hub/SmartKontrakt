// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 31 (gas assumptions, both halves).
///  (a) withdraw() pays out with .transfer() -- the 2300-gas stipend
///      cannot cover a recipient whose receive() writes storage, so
///      the payout reverts and the funds stick.
///  (b) execute() forwards to a caller-chosen callee with a
///      HARDCODED 3000 gas -- any callee doing real work runs out of
///      gas, and the failure is swallowed.
contract StipendVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        balances[msg.sender] = 0;
        // BUG (a): fixed 2300 stipend payout.
        payable(msg.sender).transfer(amount);
    }

    function execute(address to, bytes calldata data) external {
        // BUG (b): hardcoded gas forward, result ignored.
        (bool ok, ) = to.call{gas: 3000}(data);
        ok;
    }

    receive() external payable {}
}
