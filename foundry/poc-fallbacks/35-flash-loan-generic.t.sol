// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- Generic flash loan (borrow / use / repay)
/// @notice Base pattern for every flash-loan attack (oracle, sandwich,
///         governance, liquidation): borrow a huge amount with NO
///         collateral, use it inside one transaction, repay + premium.
///         The attack body goes in executeOperation() -- and a round-trip
///         alone is NOT a verdict: this harness passes only when the
///         adapted attack body has asserted a TARGET-STATE effect and set
///         the `attackLanded` hook (see FlashBorrower). Unadapted, or
///         with only POOL / ASSET set, it cannot pass.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: set POOL (Aave v3 Pool) / ASSET /
///      amount. Aave v3 flashLoanSimple signature below; Balancer / Uniswap
///      v3 / dYdX use different callbacks -- adapt executeOperation.

interface IPool {
    function flashLoanSimple(
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IERC20 {
    function balanceOf(address who) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract FlashBorrower {
    IPool public immutable pool;
    address public immutable owner;
    // Adaptation hook: ships false and is set true ONLY by an adapted
    // attack body that has verified a target-state effect (see
    // executeOperation). The shipped body performs no attack and never
    // sets it, so the harness cannot pass on a bare round-trip.
    bool public attackLanded;

    constructor(address pool_) {
        pool = IPool(pool_);
        owner = msg.sender;
    }

    function borrow(address asset, uint256 amount) external {
        pool.flashLoanSimple(asset, amount, bytes(""), 0);
    }

    // Aave v3 callback. The borrowed funds are HERE during this call.
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address,
        bytes calldata
    ) external returns (bool) {
        // TODO: the attack body goes here (swap / vote / liquidate /
        // manipulate against POC_TARGET). Verify the TARGET-STATE effect
        // the finding claims (its price moved / its balance drained /
        // its vote swung) and set `attackLanded = true` only when that
        // effect actually holds -- then repay.
        uint256 repay = amount + premium;
        IERC20(asset).approve(address(pool), repay);
        return true;
    }
}

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: the lending pool (Aave v3 Pool on this chain) + asset.
    address public constant POOL = address(0);
    address public constant ASSET = address(0);

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
        require(POOL != address(0) && ASSET != address(0), "set POOL / ASSET");

        FlashBorrower borrower = new FlashBorrower(POOL);
        uint256 amount = 1000 ether;
        // Borrow + repay round-trips: the flash-loan primitive works.
        // That alone proves NOTHING about the target -- the verdict is
        // the hook below, which only an adapted attack body that checked
        // a target-state effect can satisfy.
        borrower.borrow(ASSET, amount);
        console.log("flash loan round-trip succeeded for amount:", amount);
        assertTrue(
            borrower.attackLanded(),
            "35-flash-loan: round-trip completed but the attack hook never fired -- no target-state assertion was wired, so nothing about POC_TARGET is proven; wire the attack + target-state check in executeOperation and set attackLanded only when it holds"
        );
    }
}
