import assert from "node:assert/strict";
import test from "node:test";
import {
  discoverDecisiveGetters,
  gatherLiveState,
  probeLiveState,
  type EthCallFn,
} from "./live-state.ts";
import type { AbiItem } from "./types.ts";

/**
 * Live-state probes (2026-10-22): discovery of decisive getters from
 * source/ABI, ABI-word decoding, and never-throw probing. RPC is
 * mocked — no live network in unit tests.
 */

const ADDR = "0x1111111111111111111111111111111111111111";

const word = (n: bigint) => "0x" + n.toString(16).padStart(64, "0");
const addrWord = (a: string) => "0x" + "0".repeat(24) + a.replace(/^0x/, "").toLowerCase();

const FIXTURE_SOURCE = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TaxToken {
    bool public paused;
    address public owner;
    uint256 public buyFee = 2;
    uint256 public _maxTxAmount = 1000000;
    uint256 private sellTax = 5;

    function tradingEnabled() external view returns (bool) {
        return true;
    }

    function sellFee() external view returns (uint256) {
        return 3;
    }

    function maxWallet() external pure returns (uint256) {
        return 500000;
    }

    function taxFee(uint256 x) external view returns (uint256) {
        return x;
    }

    function totalFees() external view returns (string memory) {
        return "n/a";
    }

    function swapEnabled() external returns (bool) {
        return true;
    }

    function setPaused(bool p) external {
        paused = p;
    }
}
`;

test("discovery from source finds decisive getters and ignores the rest", () => {
  const getters = discoverDecisiveGetters({ source: FIXTURE_SOURCE });
  assert.deepEqual(
    getters.map((g) => g.name),
    ["paused", "owner", "tradingEnabled", "buyFee", "sellFee", "_maxTxAmount", "maxWallet"],
  );
  const byName = new Map(getters.map((g) => [g.name, g]));
  assert.equal(byName.get("paused")!.kind, "bool");
  assert.equal(byName.get("owner")!.kind, "address");
  assert.equal(byName.get("buyFee")!.kind, "uint");
  // Known-constant selectors pin the keccak wiring.
  assert.equal(byName.get("paused")!.selector, "0x5c975abb");
  assert.equal(byName.get("owner")!.selector, "0x8da5cb5b");
  assert.equal(byName.get("paused")!.signature, "paused()");
  // Ignored: sellTax (private var), taxFee (takes an argument),
  // totalFees (returns string), swapEnabled (not view/pure).
});

test("discovery from ABI uses exact entries only", () => {
  const abi: AbiItem[] = [
    { type: "function", name: "paused", inputs: [], outputs: [{ type: "bool" }], stateMutability: "view" },
    { type: "function", name: "getOwner", inputs: [], outputs: [{ type: "address" }], stateMutability: "view" },
    { type: "function", name: "buyFee", inputs: [], outputs: [{ type: "uint256" }], stateMutability: "view" },
    { type: "function", name: "transfer", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }], stateMutability: "nonpayable" },
    { type: "function", name: "sellFee", inputs: [{ type: "uint256" }], outputs: [{ type: "uint256" }], stateMutability: "view" },
    { type: "function", name: "totalFees", inputs: [], outputs: [{ type: "uint256" }, { type: "uint256" }], stateMutability: "view" },
    { type: "event", name: "paused", inputs: [], outputs: [{ type: "bool" }], stateMutability: "view" },
  ];
  const getters = discoverDecisiveGetters({ abi });
  assert.deepEqual(getters.map((g) => g.name), ["paused", "getOwner", "buyFee"]);
});

test("probe decodes bool / address / uint and stamps the block number", async () => {
  const getters = discoverDecisiveGetters({ source: FIXTURE_SOURCE });
  const sel = new Map(getters.map((g) => [g.name, g.selector]));
  const bigUint = 2n ** 200n + 5n;
  const callFn: EthCallFn = async (_address, calldata) => {
    switch (calldata) {
      case sel.get("paused"):
        return { success: true, result: word(1n) };
      case sel.get("owner"):
        // Resolve last on purpose: report order must follow candidate
        // order, not completion order.
        await new Promise((r) => setTimeout(r, 20));
        return { success: true, result: addrWord("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48") };
      case sel.get("tradingEnabled"):
        return { success: true, result: word(0n) };
      case sel.get("buyFee"):
        return { success: true, result: word(2500n) };
      case sel.get("sellFee"):
        return { success: true, result: word(3n) };
      case sel.get("_maxTxAmount"):
        return { success: true, result: word(bigUint) };
      case sel.get("maxWallet"):
        return { success: true, result: word(500000n) };
      default:
        return { success: false, error: "unexpected calldata" };
    }
  };
  const report = await probeLiveState(ADDR, "ethereum", getters, {
    callFn,
    blockNumberFn: async () => 12345678,
  });
  assert.equal(report.blockNumber, 12345678);
  assert.equal(report.failures.length, 0);
  assert.deepEqual(
    report.reads.map((r) => [r.name, r.value]),
    [
      ["paused", "true"],
      ["owner", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"],
      ["tradingEnabled", "false"],
      ["buyFee", "2500"],
      ["sellFee", "3"],
      ["_maxTxAmount", bigUint.toString()],
      ["maxWallet", "500000"],
    ],
  );
  assert.equal(report.reads[0]!.raw, word(1n));
  assert.equal(report.reads[1]!.kind, "address");
});

test("RPC failures are recorded, partial results kept, nothing throws", async () => {
  const getters = discoverDecisiveGetters({ source: FIXTURE_SOURCE });
  const sel = new Map(getters.map((g) => [g.name, g.selector]));
  const callFn: EthCallFn = async (_address, calldata) => {
    if (calldata === sel.get("paused")) return { success: true, result: word(0n) };
    if (calldata === sel.get("owner")) throw new Error("socket hangup");
    return { success: false, error: "RPC nodes unreachable or timed out" };
  };
  const report = await probeLiveState(ADDR, "ethereum", getters, {
    callFn,
    blockNumberFn: async () => {
      throw new Error("no block");
    },
  });
  assert.equal(report.blockNumber, null);
  assert.deepEqual(report.reads.map((r) => r.name), ["paused"]);
  assert.equal(report.reads[0]!.value, "false");
  const failByName = new Map(report.failures.map((f) => [f.name, f.error]));
  assert.equal(failByName.get("owner"), "socket hangup");
  assert.match(failByName.get("buyFee")!, /RPC nodes unreachable/);
  assert.equal(report.failures.length, getters.length - 1);
});

test("empty result (0x) is a failure, not a read", async () => {
  const getters = discoverDecisiveGetters({
    abi: [{ type: "function", name: "paused", inputs: [], outputs: [{ type: "bool" }], stateMutability: "view" }],
  });
  const report = await probeLiveState(ADDR, "ethereum", getters, {
    callFn: async () => ({ success: true, result: "0x" }),
    blockNumberFn: async () => 1,
  });
  assert.equal(report.reads.length, 0);
  assert.equal(report.failures.length, 1);
  assert.match(report.failures[0]!.error, /empty result/);
});

test("no getters: empty report, zero RPC traffic, gather returns null", async () => {
  let calls = 0;
  const callFn: EthCallFn = async () => {
    calls++;
    return { success: true, result: word(1n) };
  };
  const report = await probeLiveState(ADDR, "ethereum", [], {
    callFn,
    blockNumberFn: async () => {
      calls++;
      return 1;
    },
  });
  assert.deepEqual(report.reads, []);
  assert.deepEqual(report.failures, []);
  assert.equal(report.blockNumber, null);
  assert.equal(calls, 0);

  const none = await gatherLiveState(ADDR, "ethereum", {
    source: "contract Plain { function transfer() external {} }",
    abi: [],
  });
  assert.equal(none, null);
});

test("a hung RPC lands in failures at the deadline instead of stalling", async () => {
  const getters = discoverDecisiveGetters({
    abi: [{ type: "function", name: "paused", inputs: [], outputs: [{ type: "bool" }], stateMutability: "view" }],
  });
  const callFn: EthCallFn = () =>
    new Promise((resolve) => setTimeout(() => resolve({ success: true, result: word(1n) }), 500));
  const started = Date.now();
  const report = await probeLiveState(ADDR, "ethereum", getters, {
    callFn,
    blockNumberFn: async () => 7,
    deadlineMs: 40,
  });
  assert.ok(Date.now() - started < 400, "probe returned at the deadline, not at RPC speed");
  assert.equal(report.reads.length, 0);
  assert.equal(report.failures.length, 1);
  assert.match(report.failures[0]!.error, /deadline/);
});
