// src/lib/audit/simulator.test.ts
//
// Producer tests for the live-probe module (G4). Covered: the pure
// display-name rules (probeOnChainName sanitization, resolveContract-
// DisplayName ordering — the Item 1 label rule every surface shares)
// and the JSON-RPC plumbing (executeEthCall success / revert / RPC
// rotation, fetchLatestBlockNumber, probeContractInterfaces decoding)
// against a stubbed global fetch — no live network.
//
// Deliberately NOT covered: behavior against real RPC endpoints
// (latency, provider quirks, rate-limit interplay under load). Those
// are integration properties; the unit contract pinned here is what
// the module does with a given RPC response.
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  executeEthCall,
  fetchLatestBlockNumber,
  probeContractInterfaces,
  probeOnChainName,
  resolveContractDisplayName,
  type CallProbeResult,
} from "./simulator.ts";
import type { Report } from "./types.ts";

const probe = (partial: Partial<CallProbeResult>): CallProbeResult => ({
  selector: "0x06fdde03",
  name: "name()",
  success: true,
  ...partial,
});

describe("probeOnChainName — the Item 1 sanitization gate", () => {
  it("returns a clean probed name", () => {
    assert.equal(probeOnChainName([probe({ decodedString: "The Baller Bananas" })]), "The Baller Bananas");
  });

  it("trims surrounding whitespace before judging", () => {
    assert.equal(probeOnChainName([probe({ decodedString: "  Token  " })]), "Token");
  });

  it("rejects failed probes, missing probes and empty values", () => {
    assert.equal(probeOnChainName([probe({ success: false, decodedString: "Token" })]), null);
    assert.equal(probeOnChainName([probe({ name: "symbol()", decodedString: "TKN" })]), null);
    assert.equal(probeOnChainName([probe({ decodedString: "   " })]), null);
    assert.equal(probeOnChainName([]), null);
    assert.equal(probeOnChainName(null), null);
    assert.equal(probeOnChainName(undefined), null);
  });

  it("rejects non-names: an address, an over-long blob, control characters", () => {
    assert.equal(
      probeOnChainName([probe({ decodedString: "0x1234567890abcdef1234567890abcdef12345678" })]),
      null,
    );
    assert.equal(probeOnChainName([probe({ decodedString: "x".repeat(121) })]), null);
    assert.equal(probeOnChainName([probe({ decodedString: "Bad\tName" })]), null);
  });
});

const reportStub = (partial: Partial<Report>): Report =>
  ({
    label: "fallback-label",
    inventory: { contractNames: ["FirstInFile"] },
    mainContract: null,
    ...partial,
  }) as Report;

describe("resolveContractDisplayName — probe > analyzed > first-in-file > label", () => {
  it("the on-chain name() probe wins over everything", () => {
    const report = reportStub({ mainContract: "Analyzed" });
    assert.equal(
      resolveContractDisplayName([probe({ decodedString: "On Chain Name" })], report),
      "On Chain Name",
    );
  });

  it("a rejected probe falls through to the analyzed (main) contract", () => {
    const report = reportStub({ mainContract: "Analyzed" });
    assert.equal(resolveContractDisplayName([probe({ success: false })], report), "Analyzed");
    assert.equal(resolveContractDisplayName(null, report), "Analyzed");
  });

  it("no main contract → first contract in the file → the record label", () => {
    assert.equal(resolveContractDisplayName(null, reportStub({})), "FirstInFile");
    const bare = reportStub({ inventory: { contractNames: [] } as unknown as Report["inventory"] });
    assert.equal(resolveContractDisplayName(null, bare), "fallback-label");
  });
});

// ---------------------------------------------------------------------
// RPC plumbing against a stubbed fetch. The stub answers per-URL so
// rotation can be observed: `handlers` maps a URL substring to a
// response factory; anything unmatched throws (endpoint down).
// ---------------------------------------------------------------------

type FetchHandler = (url: string, body: { method?: string; params?: unknown[] }) => unknown;
let handlers: Array<{ match: string; respond: FetchHandler }> = [];
let calls: string[] = [];
const realFetch = globalThis.fetch;

function jsonResponse(payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

beforeEach(() => {
  handlers = [];
  calls = [];
  globalThis.fetch = (async (input: unknown, init?: { body?: string }) => {
    const url = String(input);
    calls.push(url);
    const body = init?.body ? (JSON.parse(init.body) as { method?: string; params?: unknown[] }) : {};
    for (const h of handlers) {
      if (url.includes(h.match)) return jsonResponse(h.respond(url, body));
    }
    throw new Error("endpoint down");
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

const ALL_RPCS = ""; // substring of every URL — the catch-all handler key

describe("executeEthCall (stubbed RPC)", () => {
  it("returns the result of a successful eth_call", async () => {
    handlers = [{ match: ALL_RPCS, respond: () => ({ jsonrpc: "2.0", id: 1, result: "0x1234" }) }];
    const out = await executeEthCall("0xabc", "0x06fdde03", "ethereum");
    assert.deepEqual(out, { success: true, result: "0x1234" });
  });

  it("a JSON-RPC error is a revert answer, not a retry: success=false with the message", async () => {
    handlers = [
      { match: ALL_RPCS, respond: () => ({ jsonrpc: "2.0", id: 1, error: { message: "execution reverted" } }) },
    ];
    const out = await executeEthCall("0xabc", "0x06fdde03", "ethereum");
    assert.equal(out.success, false);
    assert.equal(out.error, "execution reverted");
    assert.equal(calls.length, 1); // answered by the first endpoint — no rotation
  });

  it("rotates to the next RPC when an endpoint is down", async () => {
    // First handler (matched first) throws for every URL it sees until
    // the second distinct endpoint is tried: emulate by failing the
    // first N calls globally.
    let seen = 0;
    handlers = [
      {
        match: ALL_RPCS,
        respond: () => {
          seen += 1;
          if (seen <= 2) throw new Error("down");
          return { jsonrpc: "2.0", id: 1, result: "0xbeef" };
        },
      },
    ];
    const out = await executeEthCall("0xabc", "0x06fdde03", "ethereum");
    assert.deepEqual(out, { success: true, result: "0xbeef" });
    assert.ok(calls.length >= 2, "expected rotation across endpoints");
  });
});

describe("fetchLatestBlockNumber (stubbed RPC)", () => {
  it("parses the hex block number", async () => {
    handlers = [{ match: ALL_RPCS, respond: () => ({ jsonrpc: "2.0", id: 1, result: "0x10" }) }];
    assert.equal(await fetchLatestBlockNumber("ethereum"), 16);
  });
});

describe("probeContractInterfaces (stubbed RPC)", () => {
  it("decodes name()/decimals() and marks unimplemented probes as failures", async () => {
    const nameWord = "0x" + Buffer.from("TestToken", "utf8").toString("hex").padEnd(64, "0");
    const decimalsWord = "0x" + (18).toString(16).padStart(64, "0");
    handlers = [
      {
        match: ALL_RPCS,
        respond: (_url, body) => {
          const data = (body.params?.[0] as { data?: string } | undefined)?.data;
          if (data === "0x06fdde03") return { jsonrpc: "2.0", id: 1, result: nameWord };
          if (data === "0x313ce567") return { jsonrpc: "2.0", id: 1, result: decimalsWord };
          return { jsonrpc: "2.0", id: 1, result: "0x" };
        },
      },
    ];
    const probes = await probeContractInterfaces("0xabc", "ethereum");
    assert.equal(probes.length, 7); // the full COMMON_PROBES set
    const name = probes.find((p) => p.name === "name()");
    assert.ok(name);
    assert.equal(name.success, true);
    assert.equal(name.decodedString, "TestToken");
    const decimals = probes.find((p) => p.name === "decimals()");
    assert.ok(decimals);
    assert.equal(decimals.success, true);
    assert.equal(decimals.decodedNumber, "18");
    const owner = probes.find((p) => p.name === "owner()");
    assert.ok(owner);
    assert.equal(owner.success, false); // empty result → not implemented
  });
});
