import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { analyzeAddress } from "./address-fetcher.ts";
import { riskScore } from "./risk.ts";
import type { ResnetResult } from "./resnet-result.ts";

/**
 * Coverage + fetch-completeness pins for analyzeAddress, with the whole
 * network stubbed at globalThis.fetch (Sourcify files + metadata, public
 * RPC, price hosts). Two entry kinds exist — verified-source and
 * bytecode-only — and both must end the audit with:
 *   (a) every consumer input attached: source findings AND runtime
 *       bytecode AND an ABI (the verified path returning source-only
 *       and starving bytecode consumers was a real bug in this repo);
 *   (b) the injected ResNet runner invoked exactly once, over the
 *       RUNTIME code (never over source text);
 *   (c) the score carrying the bounded ML term when findings exist.
 */

const ADDRESS = "0x1111111111111111111111111111111111111111";

// Real deployed runtime bytecode (the model's parity corpus case 0) so
// the bytecode analyzer, heuristic ABI and screening all see real code.
const parity = JSON.parse(
  readFileSync(new URL("../../../public/models/resnet1d-parity.json", import.meta.url), "utf8"),
) as { cases: { bytecode: string }[] };
const RUNTIME_CODE = parity.cases[0].bytecode;

const SOURCE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    mapping(address => uint256) public balances;
    constructor() { owner = msg.sender; }
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
`;

const SOURCIFY_ABI = [
  { type: "function", name: "withdraw", inputs: [], outputs: [], stateMutability: "nonpayable" },
  { type: "function", name: "deposit", inputs: [], outputs: [], stateMutability: "payable" },
];

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
    inputBytes: RUNTIME_CODE.replace(/^0x/i, "").length / 2,
    truncated: false,
    ranAt: "2026-10-24T00:00:00.000Z",
  };
}

function installFetch(mode: "verified" | "bytecode") {
  const original = globalThis.fetch;
  const stub = async (input: unknown, init?: { method?: string; body?: string | null }) => {
    const url = String(input);
    const json = (obj: unknown, status = 200) =>
      new Response(JSON.stringify(obj), {
        status,
        headers: { "Content-Type": "application/json" },
      });
    if (url.includes("sourcify.dev/server/files/any/")) {
      return mode === "verified"
        ? json({ files: [{ name: "Vault.sol", content: SOURCE }] })
        : json({ error: "not found" }, 404);
    }
    if (url.includes("repo.sourcify.dev/contracts/")) {
      return mode === "verified" ? json({ output: { abi: SOURCIFY_ABI } }) : json({}, 404);
    }
    if (init?.method === "POST" && typeof init.body === "string") {
      const body = JSON.parse(init.body) as { method?: string };
      if (body.method === "eth_getCode") return json({ jsonrpc: "2.0", id: 1, result: RUNTIME_CODE });
      if (body.method === "eth_getBalance") return json({ jsonrpc: "2.0", id: 1, result: "0x0" });
      if (body.method === "eth_call") {
        return json({ jsonrpc: "2.0", id: 1, result: `0x${"0".repeat(64)}` });
      }
      return json({ jsonrpc: "2.0", id: 1, result: null });
    }
    return json({}, 404);
  };
  globalThis.fetch = stub as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}

test("verified entry: source + runtime bytecode + ABI attached, resnet runs over the runtime code", async () => {
  const restore = installFetch("verified");
  try {
    const seen: string[] = [];
    const { report, inputKind } = await analyzeAddress(ADDRESS, "ethereum", undefined, {
      resnetRunner: async (code) => {
        seen.push(code);
        return stubResult();
      },
    });
    assert.equal(inputKind, "source");
    // Fetch completeness: all three consumer inputs present.
    assert.ok(report.findings.some((f) => f.detector === "reentrancy"), "source findings present");
    assert.equal(report.runtimeBytecode?.code, RUNTIME_CODE, "runtime bytecode bound to the report");
    assert.equal(report.inventory.abiSource, "sourcify");
    assert.deepEqual(report.inventory.abi, SOURCIFY_ABI);
    // Coverage: exactly one screening, over the runtime code — not the source.
    assert.deepEqual(seen, [RUNTIME_CODE]);
    assert.equal(report.resnet?.modelId, "stub-model");
    // Scoring: the stored score is the static score plus the ML term.
    assert.equal(report.riskScore, riskScore(report.findings, stubResult()));
    assert.ok(report.riskScore > riskScore(report.findings));
  } finally {
    restore();
  }
});

test("bytecode entry: bytecode + heuristic ABI attached, resnet runs over the fetched code", async () => {
  const restore = installFetch("bytecode");
  try {
    const seen: string[] = [];
    const { report, inputKind, rawBody } = await analyzeAddress(ADDRESS, "ethereum", undefined, {
      resnetRunner: async (code) => {
        seen.push(code);
        return stubResult();
      },
    });
    assert.equal(inputKind, "bytecode");
    assert.equal(rawBody, RUNTIME_CODE);
    // Fetch completeness for the unverified kind: no source exists, but
    // the ABI is still attached (heuristic rebuild from the analysis).
    assert.ok(report.inventory.abi && report.inventory.abi.length > 0, "heuristic ABI attached");
    assert.equal(report.inventory.abiSource, "heuristic");
    // Coverage: exactly one screening, over the fetched runtime code.
    assert.deepEqual(seen, [RUNTIME_CODE]);
    assert.equal(report.resnet?.modelId, "stub-model");
    // Scoring discipline: this code yields no static findings, so the
    // ML flag is recorded as evidence and the score stays 0.
    assert.equal(report.findings.length, 0);
    assert.equal(report.riskScore, 0);
    assert.match(report.inventory.notes.at(-1)!, /evidence only/);
  } finally {
    restore();
  }
});

test("without an injected Node runner the audit records unavailable and keeps static score", async () => {
  const restore = installFetch("verified");
  try {
    const { report } = await analyzeAddress(ADDRESS, "ethereum");
    assert.equal(report.resnet, null);
    assert.equal(report.inventory.resnetStatus?.status, "unavailable");
    assert.equal(report.riskScore, riskScore(report.findings));
  } finally {
    restore();
  }
});
