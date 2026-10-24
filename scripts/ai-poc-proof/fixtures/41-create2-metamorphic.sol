// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 41 (CREATE2 metamorphic redeploy).
/// VULNERABLE BY DESIGN: this is the target SYSTEM the gated template
/// judges -- a factory that deploys its occupant via CREATE2 from a
/// constant init-code stub, so the occupant's address is fixed (factory
/// + salt + the stub's init hash) while the code installed there is
/// whatever runtime the factory currently points at. The occupant
/// exposes an unauthenticated kill(): anyone can destroy the current
/// incarnation, and -- inside the same transaction, the only form that
/// survives EIP-6780 -- the factory can then install DIFFERENT code at
/// the SAME address. Anyone trusting "this address is that code" is
/// trusting a mutable binding. POC_TARGET is the factory's CREATE2
/// address for the suite's salt (addressFor), not a direct deployment.
interface IStageFactory41 {
    function currentRuntime() external view returns (bytes memory);
}

/// Constant CREATE2 init code: installs the factory's current runtime.
/// Constant across stages -- that is what makes the address identical
/// for every incarnation.
contract StageStub41 {
    constructor() {
        bytes memory runtime = IStageFactory41(msg.sender).currentRuntime();
        assembly {
            return(add(runtime, 0x20), mload(runtime))
        }
    }
}

contract StageOne41 {
    function version() external pure returns (uint256) {
        return 1;
    }

    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}

contract StageTwo41 {
    function version() external pure returns (uint256) {
        return 2;
    }

    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}

contract FixtureFactory41 {
    bytes public currentRuntime;

    constructor() {
        currentRuntime = type(StageOne41).runtimeCode;
    }

    /// The CREATE2 address this factory's cycle manages for `salt` --
    /// the suite resolves POC_TARGET through this view.
    function addressFor(bytes32 salt) external view returns (address) {
        bytes32 initHash = keccak256(type(StageStub41).creationCode);
        return
            address(
                uint160(
                    uint256(
                        keccak256(
                            abi.encodePacked(bytes1(0xff), address(this), salt, initHash)
                        )
                    )
                )
            );
    }

    /// Stage one: deploy the current (StageOne41) incarnation at the
    /// CREATE2 address for `salt`.
    function deploy(bytes32 salt) external returns (address addr) {
        bytes memory init = type(StageStub41).creationCode;
        assembly {
            addr := create2(0, add(init, 0x20), mload(init), salt)
        }
        require(addr != address(0), "deploy failed");
    }

    /// Stage two: point the stub at StageTwo41 and deploy at the SAME
    /// CREATE2 address. Only lands if the first incarnation was
    /// destroyed in the same transaction (EIP-6780).
    function redeploy(bytes32 salt) external returns (address addr) {
        currentRuntime = type(StageTwo41).runtimeCode;
        bytes memory init = type(StageStub41).creationCode;
        assembly {
            addr := create2(0, add(init, 0x20), mload(init), salt)
        }
        require(addr != address(0), "redeploy failed");
    }
}
