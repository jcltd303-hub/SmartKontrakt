import test from "node:test";
import assert from "node:assert/strict";
import { riskScore, riskBand, worstFinding, SEVERITY_FLOOR } from "./risk.ts";
import type { Finding, Severity } from "./types.ts";

function f(severity: Severity, over: Partial<Finding> = {}): Finding {
  return {
    id: `${severity}-${Math.random().toString(36).slice(2, 7)}`,
    severity,
    swc: null,
    title: `${severity} issue`,
    confidence: "high",
    detector: "test",
    summary: "",
    walkthrough: "",
    exploitSolidity: "",
    remediationSolidity: "",
    locationFn: null,
    locationLine: null,
    snippet: "",
    ...over,
  };
}

test("a single critical lands in the critical band (the bug being fixed)", () => {
  const score = riskScore([f("critical")]);
  assert.ok(score >= 75, `one critical scored ${score}, expected the critical band`);
  assert.equal(riskBand(score), "critical");
});

test("a critical plus a high is no longer stuck in the 40s", () => {
  const score = riskScore([f("critical"), f("high")]);
  assert.ok(score >= 75, `critical+high scored ${score}`);
  assert.equal(riskBand(score), "critical");
});

test("each severity alone lands in its own band", () => {
  assert.equal(riskBand(riskScore([f("critical")])), "critical");
  assert.equal(riskBand(riskScore([f("high")])), "high");
  assert.equal(riskBand(riskScore([f("medium")])), "medium");
  assert.equal(riskBand(riskScore([f("low")])), "low");
});

test("no findings is zero, and info-only is not a risk signal", () => {
  assert.equal(riskScore([]), 0);
  assert.equal(riskBand(0), "none");
  assert.equal(riskScore([f("info")]), 0);
});

test("volume never overtakes severity", () => {
  const manyMediums = Array.from({ length: 10 }, () => f("medium"));
  assert.ok(riskScore(manyMediums) < SEVERITY_FLOOR.critical);
  assert.notEqual(riskBand(riskScore(manyMediums)), "critical");
  // ...and the volume term is bounded, not linear.
  assert.ok(riskScore(manyMediums) <= SEVERITY_FLOOR.medium + 12);
});

test("a reproduced exploit outranks the same finding as a lead", () => {
  const lead = riskScore([f("high")]);
  const proven = riskScore([f("high", { pocStatus: "passed" })]);
  assert.ok(proven > lead, `proven ${proven} should exceed lead ${lead}`);
  assert.equal(riskBand(proven), "high", "a proven high is still high — but ranked above the lead");
  // A confirmed CRITICAL is unambiguously critical-grade.
  assert.equal(riskBand(riskScore([f("critical", { pocStatus: "passed" })])), "critical");
});

test("the score is clamped to 0-100", () => {
  const everything = [
    f("critical", { pocStatus: "passed" }),
    f("critical", { pocStatus: "passed" }),
    ...Array.from({ length: 40 }, () => f("critical")),
  ];
  assert.equal(riskScore(everything), 100);
});

test("worstFinding picks by severity, not order", () => {
  assert.equal(worstFinding([f("low"), f("critical"), f("high")])?.severity, "critical");
  assert.equal(worstFinding([]), null);
});
