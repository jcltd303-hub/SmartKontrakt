import test from "node:test";
import assert from "node:assert/strict";
import { register } from "node:module";
import { attachResnetToReport } from "../audit/resnet-attach.ts";
import { analyzeInput } from "../audit/engine.ts";

/**
 * Simulate the phone failure mode without uninstalling anything: make
 * module resolution fail for the optional ONNX runtime package. The
 * Node runner module must still load, its screening calls must resolve
 * null, and attaching that runner preserves static findings while recording missing evidence.
 */
const onnxAbsenceHook = `
export async function resolve(specifier, context, nextResolve) {
  if (
    specifier === "onnxruntime-node" ||
    specifier.startsWith("onnxruntime-node/") ||
    specifier === "onnxruntime-web" ||
    specifier.startsWith("onnxruntime-web/")
  ) {
    const error = new Error(
      "Cannot find package '" + specifier + "' (simulated absence)",
    );
    error.code = "ERR_MODULE_NOT_FOUND";
    throw error;
  }
  return nextResolve(specifier, context);
}
`;
register(`data:text/javascript,${encodeURIComponent(onnxAbsenceHook)}`);

const SOME_BYTECODE =
  "0x60806040526004361061003f5760003560e01c80633c21b5e2146100445780632e64cec114610064575b600080fd";

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

test("missing ONNX runtime: module loads, runner resolves null, static audit survives with explicit status", async () => {
  const warnings: string[] = [];
  const originalWarn = console.warn;
  console.warn = (...args: unknown[]) => {
    warnings.push(args.map(String).join(" "));
  };

  try {
    const { runResnetNode } = await import("./resnet-node.server.ts");
    assert.equal(typeof runResnetNode, "function");
    assert.equal(await runResnetNode(SOME_BYTECODE), null);
    assert.equal(await runResnetNode(SOME_BYTECODE), null);

    const report = analyzeInput(VAULT_SOURCE, "Vault");
    const before = JSON.stringify(report);
    const attached = await attachResnetToReport(report, SOME_BYTECODE, runResnetNode);
    assert.equal(attached, false);
    assert.equal(report.resnet, null);
    assert.deepEqual(report.findings, JSON.parse(before).findings);
    assert.equal(report.riskScore, JSON.parse(before).riskScore);
    assert.equal(report.inventory.resnetStatus?.status,"unavailable");
  } finally {
    console.warn = originalWarn;
  }

  const unavailableWarnings = warnings.filter((line) =>
    line.includes("[resnet] ResNet screening unavailable: ONNX runtime could not be loaded"),
  );
  assert.equal(unavailableWarnings.length, 1);
  assert.match(unavailableWarnings[0]!, /simulated absence/);
  assert.match(unavailableWarnings[0]!, /static analysis only/);
});
