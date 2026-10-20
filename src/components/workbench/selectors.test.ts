import assert from "node:assert/strict";
import { test } from "node:test";
import type { Finding } from "@/lib/audit/types";
import { filterFindings, getRiskColor } from "./selectors.ts";

const finding = (overrides: Partial<Finding> = {}): Finding => ({
  id: "one",
  severity: "high",
  swc: null,
  title: "Unsafe withdrawal",
  confidence: "high",
  detector: "reentrancy",
  summary: "Funds can be drained",
  walkthrough: "",
  exploitSolidity: "",
  remediationSolidity: "",
  locationFn: null,
  locationLine: null,
  snippet: "",
  ...overrides,
});

test("finding search combines severity with normalized text across all displayed metadata", () => {
  const a = finding({ swc: "107", locationFn: "withdrawFunds" });
  const b = finding({
    id: "two",
    severity: "low",
    title: "Access issue",
    detector: "access-control",
    summary: "Owner check",
  });
  const findings = [a, b];
  for (const query of [" WITHDRAWAL ", "REENTRANCY", "107", "withdrawFunds", "DRAINED"]) {
    assert.deepEqual(filterFindings(findings, "all", query), [a]);
  }
  assert.deepEqual(filterFindings(findings, "low", "withdrawal"), []);
  assert.deepEqual(filterFindings(findings, "low", "  "), [b]);
  assert.deepEqual(filterFindings(findings, "all", ""), findings);
  assert.equal(findings[0], a);
});

test("finding search handles absent optional metadata and preserves original order and identities", () => {
  const a = finding();
  const b = finding({ id: "two" });
  assert.deepEqual(filterFindings([a, b], "all", "missing"), []);
  const selected = filterFindings([b, a], "high", "");
  assert.equal(selected[0], b);
  assert.equal(selected[1], a);
  assert.deepEqual(filterFindings([], "all", ""), []);
});

test("risk labels retain their inclusive score thresholds", () => {
  for (const [score, label] of [
    [0, "CLEAN / NO HITS"],
    [1, "LOW RISK"],
    [19, "LOW RISK"],
    [20, "MEDIUM RISK"],
    [49, "MEDIUM RISK"],
    [50, "HIGH RISK"],
    [79, "HIGH RISK"],
    [80, "CRITICAL"],
    [100, "CRITICAL"],
  ] as const) {
    assert.equal(getRiskColor(score).label, label);
  }
});
