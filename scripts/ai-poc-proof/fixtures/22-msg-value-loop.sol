// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 22 (msg.value used inside a loop).
/// VULNERABLE BY DESIGN: buy() checks the payment ONCE
/// (msg.value >= PRICE, the per-item price), then loops: every
/// iteration credits another item AND refunds a slice of the payment
/// computed from the ORIGINAL msg.value -- msg.value does not decrease
/// per iteration, so after n iterations the buyer holds n items and
/// (essentially) the whole payment back. One PRICE buys n items.
contract MsgValueCashback {
    uint256 public constant PRICE = 1 ether;
    mapping(address => uint256) public itemsOf;

    function buy(uint256 n) external payable {
        require(n > 0, "empty order");
        require(msg.value >= PRICE, "price not met");
        for (uint256 i = 0; i < n; i++) {
            itemsOf[msg.sender] += 1;
            // BUG: msg.value referenced inside the loop -- the refund
            // leg re-reads the full, un-decremented msg.value on every
            // iteration instead of tracking what was actually spent.
            (bool ok, ) = msg.sender.call{value: msg.value / n}("");
            require(ok, "cashback failed");
        }
    }

    receive() external payable {}
}
