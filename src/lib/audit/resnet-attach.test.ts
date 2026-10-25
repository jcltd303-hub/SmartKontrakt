import test from "node:test";
import assert from "node:assert/strict";
import { attachResnetToReport, runtimeCodeForReport } from "./resnet-attach.ts";
import { riskScore } from "./risk.ts";
import { analyzeInput } from "./engine.ts";
import type { ResnetResult } from "./resnet-result.ts";

function stubResult(): ResnetResult {
  return {
    modelId: "stub-model",
    architecture: "upstream-resnet1d-16384-v1",
    checkpointSha256: "a".repeat(64),
    predictions: [
      { label: "access-control", score: 0.1, threshold: 0.575, flagged: false },
      { label: "arithmetic", score: 0.1, threshold: 0.45, flagged: false },
      { label: "reentrancy", score: 0.99, threshold: 0.5, flagged: true },
      { label: "unchecked-calls", score: 0.1, threshold: 0.3, flagged: false },
      { label: "others", score: 0.1, threshold: 0.275, flagged: false },
    ],
    inputBytes: 100,
    truncated: false,
    ranAt: "2026-10-24T00:00:00.000Z",
  };
}

const VAULT_SOURCE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
`;

// A small runtime: PUSH4 selectors + STOP padding; enough for the
// bytecode analyzer to produce a report.
const SOME_BYTECODE = "0x60806040526004361061003f5760003560e01c80633c21b5e2146100445780632e64cec114610064575b600080fd";

test("attach stores the result, rescores with the bounded term, and notes exactly once", async () => {
  const report = analyzeInput(VAULT_SOURCE, "Vault");
  const staticScore = riskScore(report.findings);
  assert.equal(report.riskScore, staticScore);
  const notesBefore = report.inventory.notes.length;
  const seen: string[] = [];
  const attached = await attachResnetToReport(report, SOME_BYTECODE, async (code) => {
    seen.push(code);
    return stubResult();
  });
  assert.equal(attached, true);
  assert.deepEqual(seen, [SOME_BYTECODE]);
  assert.equal(report.resnet?.modelId, "stub-model");
  assert.equal(report.riskScore, riskScore(report.findings, stubResult()));
  assert.ok(report.riskScore > staticScore, "flagged result must raise the score here");
  assert.equal(report.inventory.notes.length, notesBefore + 1);
  assert.match(report.inventory.notes.at(-1)!, /ResNet1D screening \(stub-model\)/);
});

test("a null runner result leaves the report exactly as static analysis made it", async () => {
  const report = analyzeInput(VAULT_SOURCE, "Vault");
  const notesBefore = [...report.inventory.notes];
  const attached = await attachResnetToReport(report, SOME_BYTECODE, async () => null);
  assert.equal(attached, false);
  assert.equal(report.resnet, undefined);
  assert.equal(report.riskScore, riskScore(report.findings));
  assert.deepEqual(report.inventory.notes, notesBefore);
});

test("a throwing runner is swallowed — the audit never fails on the model", async () => {
  const report = analyzeInput(VAULT_SOURCE, "Vault");
  const attached = await attachResnetToReport(report, SOME_BYTECODE, async () => {
    throw new Error("model exploded");
  });
  assert.equal(attached, false);
  assert.equal(report.resnet, undefined);
});

test("no code, no call: the runner is not invoked without runtime bytecode", async () => {
  const report = analyzeInput(VAULT_SOURCE, "Vault");
  let calls = 0;
  const attached = await attachResnetToReport(report, null, async () => {
    calls++;
    return stubResult();
  });
  assert.equal(attached, false);
  assert.equal(calls, 0);
});

test("runtimeCodeForReport picks the right code per entry kind", () => {
  // Verified/source entry: the bound runtime bytecode, never the source.
  const sourceReport = analyzeInput(VAULT_SOURCE, "Vault");
  sourceReport.runtimeBytecode = { code: SOME_BYTECODE, sourceHash: "x" };
  assert.equal(runtimeCodeForReport(sourceReport, VAULT_SOURCE), SOME_BYTECODE);
  // Source entry whose runtime fetch failed: nothing to classify.
  const bareSource = analyzeInput(VAULT_SOURCE, "Vault");
  assert.equal(runtimeCodeForReport(bareSource, VAULT_SOURCE), null);
  // Bytecode entry: the body itself is the runtime code.
  const byteReport = analyzeInput(SOME_BYTECODE, "Bytecode");
  assert.equal(byteReport.inputKind, "bytecode");
  assert.equal(runtimeCodeForReport(byteReport, SOME_BYTECODE), SOME_BYTECODE);
  // Bytecode entry with a non-hex body: refuse rather than guess.
  assert.equal(runtimeCodeForReport(byteReport, "not hex at all"), null);
});
