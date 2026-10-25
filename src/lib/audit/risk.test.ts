import test from "node:test";
import assert from "node:assert/strict";
import { riskScore, riskBand, riskBandForChunk, RISK_LABEL, worstFinding, SEVERITY_FLOOR, MAX_RESNET_BONUS } from "./risk.ts";
import type { Finding, Severity } from "./types.ts";
import { resnetRiskBonus, type ResnetResult } from "./resnet-result.ts";

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


test("one severity vocabulary: the knowledge-base tag matches the UI band", () => {
  // The RAG chunks had their own 60/30 scale while the Records tab filtered on
  // 75/50/25, so a contract scoring 65 was tagged "critical" in the knowledge
  // base and displayed as "high" in the list. Every consumer now reads riskBand.
  assert.equal(riskBandForChunk(65), "high");
  assert.equal(riskBand(65), "high");
  assert.equal(riskBandForChunk(20), "low", "a low score must not be tagged medium");
  assert.equal(riskBandForChunk(80), "critical");
  assert.equal(riskBandForChunk(0), "info", "riskBand's \"none\" is not a chunk severity");
});

test("the chunk tag and the band agree at every boundary", () => {
  for (const score of [0, 1, 24, 25, 49, 50, 74, 75, 100]) {
    const band = riskBand(score);
    const chunk = riskBandForChunk(score);
    assert.equal(chunk === "info" ? "none" : chunk, band, `score ${score} must agree`);
  }
});

test("every band has a label, so no surface has to invent one", () => {
  for (const band of ["critical", "high", "medium", "low", "none"] as const) {
    assert.equal(typeof RISK_LABEL[band], "string");
    assert.ok(RISK_LABEL[band].length > 0);
  }
});

// ---- ResNet1D term (resnet coverage batch) -------------------------------
// The ML result is a bounded pressure term under the calibration gates:
// it amplifies existing static signal and can never create it.

function ml(scores: number[]): ResnetResult {
  const thresholds = [0.575, 0.45, 0.5, 0.3, 0.275];
  const labels = ["access-control", "arithmetic", "reentrancy", "unchecked-calls", "others"];
  return {
    modelId: "resnet1d-test",
    architecture: "upstream-resnet1d-16384-v1",
    checkpointSha256: "b".repeat(64),
    predictions: labels.map((label, i) => ({
      label,
      score: scores[i],
      threshold: thresholds[i],
      flagged: scores[i] >= thresholds[i],
    })),
    inputBytes: 1000,
    truncated: false,
    ranAt: "2026-10-24T00:00:00.000Z",
  };
}

const ML_MAX = ml([0.99, 0.99, 0.99, 0.99, 0.99]);
const ML_QUIET = ml([0.05, 0.05, 0.05, 0.05, 0.05]);

test("resnet cannot mint risk: findings-free and info-only reports are untouched", () => {
  assert.equal(riskScore([], ML_MAX), 0);
  assert.equal(riskScore([f("info")], ML_MAX), 0);
  assert.equal(riskBand(riskScore([], ML_MAX)), "none");
});

test("resnet raises a real finding's score by exactly its bounded term", () => {
  const oneDecisiveFlag = ml([0.1, 0.1, 0.99, 0.1, 0.1]);
  assert.equal(resnetRiskBonus(oneDecisiveFlag), 4);
  assert.equal(riskScore([f("high")], oneDecisiveFlag), riskScore([f("high")]) + 4);
  assert.equal(riskScore([f("high")], ML_QUIET), riskScore([f("high")]));
  assert.equal(riskScore([f("high")], null), riskScore([f("high")]));
  assert.equal(riskScore([f("high")], undefined), riskScore([f("high")]));
});

test("resnet alone can never reach the critical band — the gates hold", () => {
  // The strongest possible ML result on the strongest non-critical
  // static report still lands short of 75: a critical requires a
  // critical (or heavily corroborated high) FINDING, not a score.
  const bestHigh = riskScore([f("high")], ML_MAX);
  assert.ok(bestHigh < 75, `high + max resnet scored ${bestHigh}`);
  assert.notEqual(riskBand(bestHigh), "critical");
  assert.ok(riskScore([f("medium")], ML_MAX) < 50, "medium + max resnet stays below the high band");
  assert.ok(riskScore([f("low")], ML_MAX) < 25, "low + max resnet stays below the medium band");
});

test("the resnet delta never exceeds MAX_RESNET_BONUS, at any severity mix", () => {
  const mixes: Finding[][] = [
    [f("low")],
    [f("medium"), f("low")],
    [f("high"), f("medium"), f("medium")],
    [f("critical")],
    [f("critical", { pocStatus: "passed" }), f("high"), f("high")],
    Array.from({ length: 12 }, () => f("medium")),
  ];
  for (const findings of mixes) {
    const delta = riskScore(findings, ML_MAX) - riskScore(findings);
    assert.ok(delta >= 0 && delta <= MAX_RESNET_BONUS, `delta ${delta} out of bounds`);
  }
});

test('ML pressure cannot promote a static low finding across a severity band',()=>{
 const findings=[f('low'),...Array.from({length:6},()=>f('info'))];
 assert.equal(riskScore(findings),24);
 assert.equal(riskScore(findings,ML_MAX),24);
});
