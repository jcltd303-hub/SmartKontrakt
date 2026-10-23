// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for 43-front-running (detector: front-running).
/// A one-shot reward pool: the first `claim()` in block order takes the
/// whole pot. Nothing binds the reward to an intended recipient, so
/// whoever's transaction lands first -- a front-runner watching the
/// mempool -- wins it.
contract FrontRunReward {
    bool public claimed;

    receive() external payable {}

    /// VULNERABLE: first-come-first-served payout, no commit/reveal or
    /// recipient binding.
    function claim() public {
        require(!claimed, "already claimed");
        claimed = true;
        (bool ok,) = payable(msg.sender).call{value: address(this).balance}("");
        require(ok);
    }
}
