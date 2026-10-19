// src/lib/audit/finding-poc-audits.test.ts
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { wrapPocSnippet } from "./poc-wrap.ts";
import { deduplicateInterfaceFunctions } from "./deep-agent.server.ts";
import { isPocCompileError } from "./foundry-backend.ts";

describe("finding PoC wrapping and execution helpers", () => {
  it("wraps a recommended exploit snippet with attack() entry into a runnable Test harness", () => {
    const exploitSolidity = `interface IVault { function withdraw() external; }
contract VaultExploit {
    IVault vault;
    constructor(address v) { vault = IVault(v); }
    function attack() external payable {
        vault.withdraw();
    }
}`;

    const wrapped = wrapPocSnippet(exploitSolidity);
    assert.ok(wrapped, "should wrap valid exploit");
    assert.equal(wrapped.attackContract, "VaultExploit");
    assert.equal(wrapped.entry, "attack");
    assert.ok(wrapped.testFile.includes("contract PoC is Test"));
    assert.ok(wrapped.testFile.includes("vm.createSelectFork"));
    assert.ok(wrapped.testFile.includes("VaultExploit attacker = new VaultExploit(target);"));
    assert.ok(wrapped.testFile.includes("attacker.attack{value: 1 ether}();"));
  });

  it("passes through an already complete PoC test contract without wrapping", () => {
    const fullTest = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "forge-std/Test.sol";
contract PoC is Test {
    function test_exploit() public {
        assertTrue(true);
    }
}`;
    const wrapped = wrapPocSnippet(fullTest);
    assert.ok(wrapped);
    assert.equal(wrapped.attackContract, "<existing>");
    assert.equal(wrapped.testFile, fullTest);
  });

  it("identifies compiler error patterns accurately with isPocCompileError", () => {
    assert.equal(isPocCompileError("Error (1686): Function with same name and parameter types defined twice"), true);
    assert.equal(isPocCompileError("Compiler run failed: ParserError: Expected ';' but got '}'"), true);
    assert.equal(isPocCompileError("TypeError: Member 'deposit' not found or not visible"), true);
    assert.equal(isPocCompileError("DeclarationError: Identifier not found"), true);
    assert.equal(isPocCompileError("forge test passed 1 test"), false);
    assert.equal(isPocCompileError("transport error: connection reset by peer"), false);
  });

  it("deduplicates duplicated interface function definitions", () => {
    const codeWithDuplicates = `interface IVictim {
    function core() external;
    function core() external;
    function transfer(address to, uint256 amt) external;
    function transfer(address to, uint256 amt) external;
}
contract PoC is Test {
    function testPoc() public {}
}`;

    const cleaned = deduplicateInterfaceFunctions(codeWithDuplicates);
    const coreMatches = (cleaned.match(/function\s+core\(\)/g) ?? []).length;
    const transferMatches = (cleaned.match(/function\s+transfer/g) ?? []).length;
    assert.equal(coreMatches, 1, "core should be declared only once");
    assert.equal(transferMatches, 1, "transfer should be declared only once");
    assert.ok(cleaned.includes("contract PoC is Test"));
  });

  it("wraps the enhanced multi-step delegatecall storage collision exploit (MultiStepSmash + AdvancedTake)", () => {
    const exploitCode = `contract MultiStepSmash {
    address public owner;
    function seizeAndDrain(address token, address payable recipient) external {
        owner = msg.sender;
        if (address(this).balance > 0) {
            recipient.transfer(address(this).balance);
        }
    }
}

interface IVictim { function migrate(address impl, bytes calldata data) external; }

contract AdvancedTake {
    function executeAttack(address victim, address rewardToken, address attackerWallet) external {
        MultiStepSmash smash = new MultiStepSmash();
        bytes memory payload = abi.encodeWithSignature(
            "seizeAndDrain(address,address)",
            rewardToken,
            attackerWallet
        );
        IVictim(victim).migrate(address(smash), payload);
    }
}`;

    const wrapped = wrapPocSnippet(exploitCode);
    assert.ok(wrapped, "should wrap AdvancedTake multi-step exploit");
    assert.equal(wrapped.attackContract, "AdvancedTake");
    assert.equal(wrapped.entry, "executeAttack");
    assert.ok(wrapped.testFile.includes("AdvancedTake attacker = new AdvancedTake();"));
    assert.ok(wrapped.testFile.includes("attacker.executeAttack(target, address(attacker), address(attacker));"));
    assert.ok(wrapped.testFile.includes("contract PoC is Test"));
  });
});
