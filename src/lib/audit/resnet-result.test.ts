import test from "node:test";
import assert from "node:assert/strict";
import {
  MAX_RESNET_BONUS,
  RESNET_CLASSES,
  parseResnetJson,
  resnetFlagged,
  resnetRiskBonus,
  resnetSummaryLine,
  serializeResnet,
  type ResnetResult,
} from "./resnet-result.ts";
import { CLASSES } from "../image-ml/runtime.ts";

// The manifest's validation-selected thresholds, in class order — the
// same numbers public/models/resnet1d-v1.json pins.
const THRESHOLDS = [0.575, 0.45, 0.5, 0.3, 0.275];

function resultWith(scores: number[]): ResnetResult {
  return {
    modelId: "resnet1d-16384-train55626-epoch2-v1",
    architecture: "upstream-resnet1d-16384-v1",
    checkpointSha256: "a488b44abc0021499406012c8a8f22d08bba927a07d01e51458509f632657eae",
    predictions: RESNET_CLASSES.map((label, i) => ({
      label,
      score: scores[i],
      threshold: THRESHOLDS[i],
      flagged: scores[i] >= THRESHOLDS[i],
    })),
    inputBytes: 4321,
    truncated: false,
    ranAt: "2026-10-24T00:00:00.000Z",
  };
}

const QUIET = [0.1, 0.1, 0.1, 0.1, 0.1];

test("class order is pinned to the model's own CLASSES list", () => {
  // resnet-result.ts carries its own copy so audit code never imports
  // the image-ml runtime; this test is what keeps the copy honest.
  assert.deepEqual([...RESNET_CLASSES], [...CLASSES]);
});

test("no flagged class, no bonus — a quiet model changes nothing", () => {
  assert.equal(resnetRiskBonus(resultWith(QUIET)), 0);
  assert.equal(resnetRiskBonus(null), 0);
  assert.equal(resnetRiskBonus(undefined), 0);
  assert.deepEqual(resnetFlagged(resultWith(QUIET)), []);
});

test("one flagged class: +3, plus +1 when it clears its threshold decisively", () => {
  // reentrancy 0.60 vs threshold 0.50 → margin 0.10 (borderline) → +3.
  assert.equal(resnetRiskBonus(resultWith([0.1, 0.1, 0.6, 0.1, 0.1])), 3);
  // reentrancy 0.99 vs threshold 0.50 → margin 0.49 (decisive) → +4.
  assert.equal(resnetRiskBonus(resultWith([0.1, 0.1, 0.99, 0.1, 0.1])), 4);
  // margin exactly 0.25 counts as decisive.
  assert.equal(resnetRiskBonus(resultWith([0.1, 0.1, 0.75, 0.1, 0.1])), 4);
});

test("each additional flagged class adds +1, capped at MAX_RESNET_BONUS", () => {
  // Two flags, strongest decisive: 4 + 1 = 5.
  assert.equal(resnetRiskBonus(resultWith([0.1, 0.1, 0.99, 0.9, 0.1])), 5);
  // All five flagged decisively: 4 + 4 = 8 → capped.
  assert.equal(resnetRiskBonus(resultWith([0.99, 0.99, 0.99, 0.99, 0.99])), MAX_RESNET_BONUS);
  assert.equal(MAX_RESNET_BONUS, 6);
});

test("serialize/parse round-trips a result exactly", () => {
  const r = resultWith([0.9, 0.1, 0.99, 0.1, 0.1]);
  assert.deepEqual(parseResnetJson(serializeResnet(r)), r);
  assert.equal(serializeResnet(null), null);
});

test("parseResnetJson is fail-soft on anything malformed", () => {
  assert.equal(parseResnetJson(null), null);
  assert.equal(parseResnetJson(undefined), null);
  assert.equal(parseResnetJson(""), null);
  assert.equal(parseResnetJson("not json"), null);
  assert.equal(parseResnetJson("{}"), null);
  assert.equal(parseResnetJson("[]"), null);
  const good = resultWith(QUIET);
  // Wrong checkpoint shape.
  assert.equal(
    parseResnetJson(JSON.stringify({ ...good, checkpointSha256: "xyz" })),
    null,
  );
  // Class order tampered — predictions no longer line up with the model.
  const swapped = resultWith(QUIET);
  [swapped.predictions[0], swapped.predictions[1]] = [swapped.predictions[1], swapped.predictions[0]];
  assert.equal(parseResnetJson(JSON.stringify(swapped)), null);
  // Score outside 0..1.
  const badScore = resultWith(QUIET);
  badScore.predictions[2].score = 1.5;
  assert.equal(parseResnetJson(JSON.stringify(badScore)), null);
  // Missing a prediction.
  const short = resultWith(QUIET);
  short.predictions = short.predictions.slice(0, 4);
  assert.equal(parseResnetJson(JSON.stringify(short)), null);
});

test("summary line reports the APPLIED bonus, never the theoretical one", () => {
  const flagged = resultWith([0.1, 0.1, 0.99, 0.1, 0.1]);
  assert.match(resnetSummaryLine(flagged, 4), /\(\+4\)/);
  assert.match(resnetSummaryLine(flagged, 4), /reentrancy 0\.99/);
  // Findings-free / info-only reports apply 0 — the note must say
  // evidence-only rather than claim a score change that did not happen.
  const zeroApplied = resnetSummaryLine(flagged, 0);
  assert.match(zeroApplied, /evidence only/);
  assert.doesNotMatch(zeroApplied, /folded into the risk score/);
  const quiet = resnetSummaryLine(resultWith(QUIET), 0);
  assert.match(quiet, /no vulnerability class/);
  assert.match(quiet, /risk score unchanged/);
});
