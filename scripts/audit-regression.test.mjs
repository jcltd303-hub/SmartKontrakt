import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "vite";

test("unchecked Solidity blocks produce a detector finding without crashing", async () => {
  const server = await createServer({ configFile: false, optimizeDeps: { noDiscovery: true }, server: { middlewareMode: true }, appType: "custom" });
  try {
    const { analyzeInput } = await server.ssrLoadModule("/src/lib/audit/engine.ts");
    const result = analyzeInput("pragma solidity ^0.8.20; contract Test { uint public value; function increment(uint amount) public { unchecked { value += amount; } } }", "Unchecked");
    assert.ok(result.findings.some((f) => f.detector === "unchecked-block"));
  } finally { await server.close(); }
});
