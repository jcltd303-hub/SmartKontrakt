import test from "node:test";
import assert from "node:assert/strict";
import { attachResnetToReport, runtimeCodeForReport } from "./resnet-attach.ts";
import { riskScore } from "./risk.ts";
import { analyzeInput } from "./engine.ts";
import { parseResnetJson, type ResnetResult } from "./resnet-result.ts";

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
    inputBytes: SOME_BYTECODE.slice(2).length/2,
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

test("a null runner result preserves static analysis and records unavailable evidence", async () => {
  const report = analyzeInput(VAULT_SOURCE, "Vault");
  const notesBefore = [...report.inventory.notes];
  const attached = await attachResnetToReport(report, SOME_BYTECODE, async () => null);
  assert.equal(attached, false);
  assert.equal(report.resnet, null);
  assert.equal(report.riskScore, riskScore(report.findings));
  assert.deepEqual(report.inventory.notes.slice(0,-1), notesBefore);
  assert.equal(report.inventory.resnetStatus?.status,"unavailable");
});

test("an unavailable runner preserves static findings and records the evidence gap", async () => {
  const report = analyzeInput(VAULT_SOURCE, "Vault");
  const before = JSON.stringify(report);
  const attached = await attachResnetToReport(report, SOME_BYTECODE, async () => null);
  assert.equal(attached, false);
  assert.equal(report.resnet, null);
  assert.equal(report.riskScore, riskScore(report.findings));
  assert.deepEqual(report.findings, JSON.parse(before).findings);
  assert.equal(report.inventory.resnetStatus?.status,"unavailable");
});

test("a throwing runner is swallowed — the audit never fails on the model", async () => {
  const report = analyzeInput(VAULT_SOURCE, "Vault");
  const attached = await attachResnetToReport(report, SOME_BYTECODE, async () => {
    throw new Error("model exploded");
  });
  assert.equal(attached, false);
  assert.equal(report.resnet, null);
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

test('retry failure clears previous ML score and records unavailable evidence', async()=>{
 const report=analyzeInput(VAULT_SOURCE,'Vault');
 await attachResnetToReport(report,SOME_BYTECODE,async()=>stubResult());
 await attachResnetToReport(report,SOME_BYTECODE,async()=>null);
 assert.equal(report.resnet,null);
 assert.equal(report.riskScore,riskScore(report.findings));
 assert.equal(report.inventory.resnetStatus?.status,'unavailable');
 assert.match(report.inventory.notes.at(-1)!,/unavailable/i);
});
test('full-byte results round-trip coverage and reject inconsistent flags',()=>{
 const r={...stubResult(),processedBytes:SOME_BYTECODE.slice(2).length/2,windows:1,policy:'consecutive-16384-zero-pad-l2-class-max-v1'};
 assert.deepEqual(parseResnetJson(JSON.stringify(r)),r);
 assert.equal(parseResnetJson(JSON.stringify({...r,processedBytes:99})),null);
 assert.equal(parseResnetJson(JSON.stringify({...r,predictions:r.predictions.map(p=>({...p,flagged:!p.flagged}))})),null);
});
