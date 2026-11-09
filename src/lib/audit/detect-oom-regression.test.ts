import test from "node:test";
import assert from "node:assert/strict";
import { parseSource } from "./model.ts";
import { detectSource } from "./detect.ts";
import type { Finding } from "./types.ts";

/**
 * Regression fixtures for Fix 62 (analyzer 2026-11-09.29): the
 * walkFn IfStatement branch merge OOM.
 *
 * Both branch snapshots in scanStmt start as copies of the pre-if
 * flow (true branch scanned + snapshotted, pre-if state restored,
 * false branch scanned), so left and right already contain every
 * pre-branch read/send/call. The old merge concatenated
 * before + left + right, TRIPLING the pre-branch entries at every
 * if — after k sequential ifs the flow lists held ~3^k copies of
 * the earliest entries. ConfidentialPool._settle (dozens of
 * sequential ifs over 83 state vars) grew its readLines arrays
 * past a 4GB heap and killed the analyzer outright; no finding
 * was ever produced for the contract.
 *
 * The fix unions the two branch results with dedupe. Every
 * consumer of these lists (readLines / sendTargets / sendDetails
 * / calleeCalls) is multiplicity-insensitive (some / every /
 * find), so the merged sets — and therefore the findings — are
 * unchanged; only the memory is bounded.
 */

function analyze(src: string): Finding[] {
  const model = parseSource(src);
  assert.equal(model.parseError, null);
  return detectSource(model, src);
}

/** A function with `ifs` sequential ifs, each reading several of
 * `vars` state vars, in the ConfidentialPool._settle shape: an
 * external call up front, writes after calls, reverts in branches.
 * On the pre-fix merge this fixture's flow lists grow ~3^ifs —
 * at 30 ifs that is ~2×10^14 entries and the process dies. */
function branchBomb(vars: number, ifs: number): string {
  const decls: string[] = [];
  for (let i = 0; i < vars; i++) decls.push(`  uint256 public v${i};`);
  const reads: string[] = [];
  for (let i = 0; i < vars; i++) reads.push(`    acc += v${i};`);
  const branches: string[] = [];
  for (let i = 0; i < ifs; i++) {
    branches.push(
      `    if (acc > ${i + 1}) { v${i % vars} = acc + v${(i + 1) % vars}; } else { acc += v${(i + 2) % vars}; }`,
    );
  }
  return `
    pragma solidity ^0.8.20;
    contract BranchBomb {
    ${decls.join("\n")}
      function settle(address target) external {
        uint256 acc = 0;
    ${reads.join("\n")}
        (bool ok, ) = target.call("");
        require(ok);
    ${branches.join("\n")}
        v0 = acc;
      }
    }
  `;
}

test("Fix 62: branch-merge bomb (30 sequential ifs over 24 state vars) completes", () => {
  const findings = analyze(branchBomb(24, 30));
  // Completion IS the assertion — the pre-fix analyzer OOM-dies on
  // this shape. Findings stay within the report cap and the walker
  // still sees the call-then-write shape it exists to see.
  assert.ok(Array.isArray(findings));
  assert.ok(findings.length <= 41);
  assert.ok(findings.some((f) => f.detector === "reentrancy" || f.detector === "read-only-reentrancy" || f.detector === "unchecked-call"));
});

test("Fix 62: branch merge still unions reads from BOTH branches (read-only reentrancy consumer survives)", () => {
  // Writer: external call, then a read of the public var inside a
  // branch, then the post-call write. The in-window self-read is
  // the Fix 12 consumer; it reaches the merged flow only if the
  // true-branch read survives the union.
  const findings = analyze(`
    pragma solidity ^0.8.20;
    contract BranchRead {
      uint256 public rate;
      function poke(address target) external {
        (bool ok, ) = target.call("");
        require(ok);
        if (rate > 1) {
          rate = rate + 1;
        }
        rate = 7;
      }
    }
  `);
  assert.ok(
    findings.some((f) => f.detector === "read-only-reentrancy"),
    `expected a read-only-reentrancy finding, got: ${findings.map((f) => f.detector).join(", ")}`,
  );
});
