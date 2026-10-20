import test from "node:test";
import assert from "node:assert/strict";
import {
  sanitizePocDraft,
  normalizeSignature,
  functionSignaturesFromInventory,
} from "./sanitize.ts";

const TARGET = {
  contractName: "Vault",
  compilerVersion: "0.8.24",
  functionSignatures: ["withdraw(uint256)", "deposit()"],
};

test("aligns pragma to the target compiler version and adds the forge-std import", () => {
  const draft = `pragma solidity ^0.7.0;\ncontract PoC { }`;
  const { code, notes } = sanitizePocDraft(draft, TARGET);
  assert.match(code, /pragma solidity 0\.8\.24;/);
  assert.doesNotMatch(code, /0\.7\.0/);
  assert.match(code, /forge-std\/Test\.sol/);
  assert.ok(notes.some((n) => n.includes("aligned pragma")));
});

test("adds abicoder v2 for a legacy (<0.8) target", () => {
  const draft = `pragma solidity ^0.6.0;\ncontract PoC { }`;
  const { code } = sanitizePocDraft(draft, { ...TARGET, compilerVersion: "0.6.12" });
  assert.match(code, /pragma abicoder v2;/);
});

test("adds SPDX and a fallback pragma when neither is present", () => {
  const { code } = sanitizePocDraft(`contract PoC { }`, {
    contractName: "Vault",
    compilerVersion: null,
    functionSignatures: [],
  });
  assert.match(code, /SPDX-License-Identifier: MIT/);
  assert.match(code, /pragma solidity \^0\.8\.24;/);
});

test("removes a contract function that re-declares a target signature", () => {
  const draft = [
    `pragma solidity 0.8.24;`,
    `import {Test} from "forge-std/Test.sol";`,
    `contract VaultCopy {`,
    `  function withdraw(uint256 amount) external {`,
    `    // the model rewrote the target's own logic — must be removed`,
    `  }`,
    `  function helper() external {}`,
    `}`,
    `contract Attacker {`,
    `  function withdraw(uint256 amount) external {}`,
    `}`,
  ].join("\n");
  const { code, notes } = sanitizePocDraft(draft, TARGET);
  // VaultCopy.withdraw is removed (shadows the target); helper survives.
  assert.ok(!/function withdraw\(uint256 amount\) external \{\s*\/\/ the model/.test(code));
  assert.match(code, /function helper\(\) external \{\}/);
  // The attacker's own withdraw is NOT a re-declaration of the target and stays.
  assert.match(code, /contract Attacker/);
  assert.match(code, /function withdraw\(uint256 amount\) external \{\}/);
  assert.ok(notes.some((n) => n.includes("conflicting/duplicate")));
});

test("removes a duplicate declaration inside one container", () => {
  const draft = [
    `pragma solidity 0.8.24;`,
    `interface ITarget {`,
    `  function owner() external view returns (address);`,
    `  function owner() external view returns (address);`,
    `}`,
  ].join("\n");
  const { code } = sanitizePocDraft(draft, TARGET);
  const matches = code.match(/function owner\(\)/g) ?? [];
  assert.equal(matches.length, 1);
});

test("normalizeSignature folds address payable and parameter names", () => {
  assert.equal(normalizeSignature("transfer(address payable to, uint256 amount)"), "transfer(address,uint256)");
  assert.equal(normalizeSignature("withdraw(uint256)"), "withdraw(uint256)");
});

test("functionSignaturesFromInventory strips contract prefixes and skips constructors", () => {
  const sigs = functionSignaturesFromInventory([
    { name: "Vault.withdraw", params: "uint256 amount" },
    { name: "Vault.constructor", params: "" },
    { name: "Vault.deposit", params: "" },
  ]);
  assert.deepEqual(sigs.sort(), ["deposit()", "withdraw(uint256)"]);
});
