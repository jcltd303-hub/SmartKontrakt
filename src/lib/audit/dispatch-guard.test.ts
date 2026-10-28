import test from "node:test";
import assert from "node:assert/strict";

import { analyzeInput } from "./engine.ts";

/**
 * arbitrary-dispatch-call vs a proven guard (2026-10-28).
 *
 * Snowfork's Snowbridge Agent (0xd803472c…46a8, 1,068 ETH) was reported critical:
 *
 *   function invoke(address executor, bytes calldata data) external ... {
 *       if (msg.sender != GATEWAY) { revert Unauthorized(); }
 *       return executor.delegatecall(data);
 *   }
 *
 * GATEWAY is immutable and set to msg.sender at construction, so an external attacker
 * cannot reach it. The rule fired because it never consulted `authed` — unlike
 * bridge-message-auth. Per the standing guard-credit rule a proven guard CAPS the
 * finding; it does not erase it, because the authorised gateway forwards
 * (executor, data) and that is the Poly shape if the values are user-supplied.
 */

const hits = (src: string) =>
  analyzeInput(src, "probe", null).findings.filter((f) => f.detector === "arbitrary-dispatch-call");

test("the Snowbridge Agent is capped at high, not critical", () => {
  const src = `// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;
contract Agent {
    error Unauthorized();
    bytes32 public immutable AGENT_ID;
    address public immutable GATEWAY;
    constructor(bytes32 agentID) { AGENT_ID = agentID; GATEWAY = msg.sender; }
    receive() external payable {}
    function invoke(address executor, bytes calldata data) external returns (bool, bytes memory) {
        if (msg.sender != GATEWAY) {
            revert Unauthorized();
        }
        return executor.delegatecall(data);
    }
}`;
  const found = hits(src);
  assert.equal(found.length, 1);
  assert.equal(found[0]!.severity, "high", "a fixed-caller gate caps it");
  assert.match(found[0]!.summary, /Capped: high/);
  assert.match(found[0]!.summary, /does not forward user-supplied target and calldata/);
});

test("an unguarded dispatch to a caller-supplied target stays critical", () => {
  const src = `pragma solidity 0.8.25;
contract Router {
    function dispatch(address target, bytes calldata data) external returns (bool, bytes memory) {
        return target.delegatecall(data);
    }
}`;
  const found = hits(src);
  assert.equal(found.length, 1);
  assert.equal(found[0]!.severity, "critical");
  assert.doesNotMatch(found[0]!.summary, /Capped: high/);
});

test("a modifier-guarded dispatch is capped too", () => {
  const src = `pragma solidity 0.8.25;
contract Keeper {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    function run(address target, bytes calldata data) external onlyOwner returns (bool, bytes memory) {
        return target.delegatecall(data);
    }
}`;
  const found = hits(src);
  assert.equal(found.length, 1);
  assert.equal(found[0]!.severity, "high");
});
