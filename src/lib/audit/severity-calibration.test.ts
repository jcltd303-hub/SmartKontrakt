import test from "node:test";
import assert from "node:assert/strict";
import { calibrateFindings, withAccessControlCap } from "./severity-calibration.ts";
import type { Finding } from "./types.ts";

function finding(partial: Partial<Finding>): Finding {
  return {
    id: "t1",
    severity: "critical",
    confidence: "high",
    detector: "test",
    title: "test",
    summary: "summary",
    walkthrough: "",
    exploitSolidity: "",
    remediationSolidity: "",
    swc: null,
    locationFn: "f",
    locationLine: 1,
    snippet: "",
    ...partial,
  };
}

test("calibrateFindings keeps high-confidence criticals", () => {
  const [f] = calibrateFindings([finding({ severity: "critical", confidence: "high" })]);
  assert.equal(f.severity, "critical");
  assert.ok(!f.summary.includes("Calibrated"));
});

test("calibrateFindings caps medium-confidence criticals at high with a note", () => {
  const [f] = calibrateFindings([finding({ severity: "critical", confidence: "medium" })]);
  assert.equal(f.severity, "high");
  assert.match(f.summary, /Calibrated: critical → high/);
});

test("calibrateFindings caps low-confidence criticals and leaves non-criticals alone", () => {
  const [crit, high] = calibrateFindings([
    finding({ severity: "critical", confidence: "low" }),
    finding({ severity: "high", confidence: "medium" }),
  ]);
  assert.equal(crit.severity, "high");
  assert.equal(high.severity, "high");
  assert.ok(!high.summary.includes("Calibrated"));
});

test("withAccessControlCap caps criticals on authed functions, leaves unauthed alone", () => {
  const capped = withAccessControlCap(finding({ severity: "critical" }), true);
  assert.equal(capped.severity, "high");
  assert.match(capped.summary, /access-controlled/);
  const open = withAccessControlCap(finding({ severity: "critical" }), false);
  assert.equal(open.severity, "critical");
  const alreadyHigh = withAccessControlCap(finding({ severity: "high" }), true);
  assert.equal(alreadyHigh.severity, "high");
  assert.ok(!alreadyHigh.summary.includes("Calibrated"));
});
