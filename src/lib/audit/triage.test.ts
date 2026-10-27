import test from "node:test";
import assert from "node:assert/strict";

import { analyzeInput } from "./engine.ts";
import { readQueue, triageCounts, triageFinding, triageQueue } from "./triage.ts";
import type { Finding } from "./types.ts";

/**
 * The read queue (2026-10-27).
 *
 * The recall-first loosening left low-confidence findings with nowhere to go.
 * These pin the three questions the queue answers — reachable? how strong is the
 * evidence? how bad if true? — and the bands they produce.
 */

const OPEN_DRAIN = `pragma solidity 0.8.24;
contract Open {
    function sweep() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}`;

const GATED = `pragma solidity 0.8.24;
contract Gated {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }
    // selfdestruct fires even when the site is gated — it caps the severity and
    // records the gate instead of dropping the finding, which is what makes it
    // a usable "gated" fixture here.
    function destroy() external onlyOwner {
        selfdestruct(payable(msg.sender));
    }
}`;

function findings(src: string): Finding[] {
  return analyzeInput(src, "triage").findings;
}

test("a reachable, confident finding is read-now", () => {
  const queue = triageQueue(findings(OPEN_DRAIN));
  const first = queue[0]!;
  assert.equal(first.band, "read-now");
  assert.match(first.reason, /reachable/);
  assert.ok(first.family);
});

test("a gated finding is background, and the reason names the gate", () => {
  const queue = triageQueue(findings(GATED));
  const gated = queue.find((t) => t.finding.detector === "selfdestruct")!;
  assert.ok(gated, "the gated selfdestruct finding should exist");
  assert.equal(gated.band, "background");
  assert.match(gated.reason, /gated|GATED/i);
});

test("read-now sorts ahead of background whatever the severity", () => {
  const queue = triageQueue(findings(GATED));
  const bands = queue.map((t) => t.band);
  const firstBackground = bands.indexOf("background");
  if (firstBackground > 0) {
    assert.ok(!bands.slice(firstBackground).includes("read-now"), "a read-now entry appeared after a background one");
  }
});

test("an unresolved guard becomes read-next, not background", () => {
  const src = `pragma solidity 0.8.24;
contract Unresolved {
    function drain() external validPlayer {
        payable(msg.sender).transfer(address(this).balance);
    }
}`;
  const hit = triageQueue(findings(src)).find((t) => t.finding.detector === "unprotected-ether")!;
  assert.equal(hit.band, "read-next");
  assert.match(hit.reason, /could not be resolved/);
});

test("a money figure with no live source becomes needs-live-state", () => {
  const src = `pragma solidity 0.8.24;
contract Bridge {
    mapping(address => uint256) public balances;
    function process(address to, uint256 amount, bytes calldata proof) external {
        require(proof.length > 0, "proof");
        balances[to] += amount;
        payable(to).transfer(amount);
    }
}`;
  const hit = triageQueue(findings(src)).find((t) => t.finding.detector === "bridge-message-auth")!;
  assert.equal(hit.band, "needs-live-state");
  assert.match(hit.reason, /assumption/);
});

test("counts separate the queue from the background", () => {
  const c = triageCounts(findings(GATED));
  assert.equal(c.total, c.readNow + c.readNext + c.needsLiveState + c.background);
  assert.equal(c.actionable, c.readNow);
  assert.ok(c.background > 0, "the gated selfdestruct should land in the background");
});

test("readQueue drops the background and keeps the order", () => {
  const queue = readQueue(findings(OPEN_DRAIN));
  assert.ok(queue.length >= 1);
  for (const t of queue) assert.notEqual(t.band, "background");
});

test("triageFinding is total: every band is reachable from a real finding shape", () => {
  const base: Finding = {
    id: "x",
    severity: "high",
    title: "t",
    confidence: "high",
    detector: "unprotected-ether",
    summary: "s",
    walkthrough: "",
    exploitSolidity: "",
    remediationSolidity: "",
    locationFn: "f",
    locationLine: 1,
    snippet: "",
  };
  assert.equal(triageFinding({ ...base, reachability: "REACHABLE" }).band, "read-now");
  assert.equal(triageFinding({ ...base, reachability: "REACHABLE", confidence: "low" }).band, "read-next");
  assert.equal(triageFinding({ ...base, reachability: "NEEDS_READ" }).band, "read-next");
  assert.equal(triageFinding({ ...base, reachability: "GATED" }).band, "background");
  assert.equal(triageFinding({ ...base, reachability: null }).band, "background");
  assert.equal(triageFinding({ ...base, severity: "info", reachability: "REACHABLE" }).band, "background");
});
