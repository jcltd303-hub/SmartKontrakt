import test from "node:test";
import assert from "node:assert/strict";

import { analyzeAddress } from "./address-fetcher.ts";

/**
 * bodyOverride (2026-10-28): analyse a body we already have.
 *
 * The archive measured 1595 scans over 375 distinct bodies — 4.25 copies each, one
 * body accounting for 341 scans. With an override supplied, the registry lookups and
 * the bytecode read are skipped; everything that describes THIS deployment (value,
 * ABI, probes, ResNet) still runs, because identical code at two addresses is two
 * different deployments.
 */

const SOURCE = `
pragma solidity ^0.8.0;
contract Reused {
    address public owner;
    function withdraw() external {
        require(msg.sender == owner, "not owner");
        payable(owner).transfer(address(this).balance);
    }
}`;

test("an override skips the registries and analyses the supplied body", async () => {
  const calls: string[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (url: string | URL | Request) => {
    const u = String(typeof url === "string" ? url : url instanceof URL ? url : url.url);
    calls.push(u);
    // Any registry or explorer hit is a failure of the override.
    if (/sourcify|blockscout/.test(u)) throw new Error(`registry hit despite override: ${u}`);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;

  try {
    const { report, rawBody, inputKind } = await analyzeAddress(
      "0x000000000000000000000000000000000000dEaD",
      "ethereum",
      "Reused",
      { bodyOverride: { body: SOURCE, inputKind: "source" } },
    );
    assert.equal(inputKind, "source");
    assert.equal(rawBody, SOURCE, "the override body comes back as the payload");
    assert.ok(report.findings.length > 0, "the analysis still ran");
    assert.ok(
      report.inventory.notes.some((n) => /Body reused from an earlier scan/.test(n)),
      "the record says the body was reused, so a reader is not misled about how it was obtained",
    );
    // The override skips SOURCE acquisition and the bytecode read. Value and ABI
    // gathering still run per address — the ABI may re-hit a registry, which is
    // expected and why the assertion is about eth_getCode, not about every URL.
    assert.equal(
      calls.filter((u) => /eth_getCode/.test(u)).length +
        calls.filter((u) => /\/server\/v2\/contract\/\d+\/0x[a-fA-F0-9]{40}\?fields=sources/.test(u)).length,
      0,
      "neither the source fetch nor eth_getCode may run when a body is supplied",
    );
  } finally {
    globalThis.fetch = original;
  }
});

test("an override of bytecode is analysed as bytecode, not parsed as source", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    })) as typeof fetch;
  try {
    const { report, inputKind } = await analyzeAddress(
      "0x000000000000000000000000000000000000dEaD",
      "ethereum",
      "Reused",
      { bodyOverride: { body: "0x6080604052348015600f57600080fd5b50", inputKind: "bytecode" } },
    );
    assert.equal(inputKind, "bytecode");
    assert.equal(report.inputKind, "bytecode");
  } finally {
    globalThis.fetch = original;
  }
});
