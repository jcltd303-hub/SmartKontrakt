import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { evaluationSummary, inputCoverage, windowComparison } from "./insights.ts";

test("evaluation cards follow the actual ResNet artifact metadata", () => {
  const artifact = JSON.parse(
    readFileSync(new URL("../../../public/models/resnet1d-v1.json", import.meta.url), "utf8"),
  );
  const value = evaluationSummary(artifact.training, artifact.evaluation);
  assert.equal(value.counts.train, 55626);
  assert.equal(value.selectedEpoch, 2);
  assert.equal(value.validation.micro, 0.7374643130001206);
  assert.equal(value.test.macro, 0.7003373145916977);
});

test("RGB metadata exposes its measured test and validation macro without inventing micro", () => {
  const artifact = JSON.parse(
    readFileSync(new URL("../../../public/models/bytecode-image-v1.json", import.meta.url), "utf8"),
  );
  const value = evaluationSummary(artifact.training, artifact.evaluation);
  assert.equal(value.counts.train, 55632);
  assert.equal(value.validation.micro, null);
  assert.equal(value.validation.macro, 0.600869361999133);
  assert.equal(value.test.micro, 0.6370421974522293);
});

test("invalid metadata stays unavailable while measured zero metrics remain valid", () => {
  const value = evaluationSummary(
    { samples: { train: -1 }, selectedEpoch: "2" },
    { validation: { microF1: NaN, macroF1: 0 }, test: { microF1: 2 } },
  );
  assert.equal(value.counts.train, null);
  assert.equal(value.selectedEpoch, null);
  assert.equal(value.validation.micro, null);
  assert.equal(value.validation.macro, 0);
  assert.equal(value.test.micro, null);
});

test("coverage includes the complete runtime across consecutive windows", () => {
  assert.deepEqual(inputCoverage(32), { used: 32, omitted: 0, total: 32, fraction: 1 });
  assert.deepEqual(inputCoverage(32768), {
    used: 32768,
    omitted: 0,
    total: 32768,
    fraction: 1,
  });
  for (const invalid of [0, -1, NaN, 1.5]) assert.throws(() => inputCoverage(invalid));
});

test("offline comparison is bound to the exact selected checkpoint and validates metrics", () => {
  const sha = "a".repeat(64);
  const fixture = {
    schemaVersion: 1,
    checkpointSha256: sha,
    prefix: { validation: { microF1: 0.7, macroF1: 0.6 }, test: { microF1: 0.7, macroF1: 0.6 } },
    windows: {
      validation: { microF1: 0.69, macroF1: 0.59 },
      test: { microF1: 0.68, macroF1: 0.58 },
    },
    validationImproved: false,
    inputAuditPassed: false,
    overlappingTrainingContracts: 2,
    sharedValidationTestWindows: 1,
    seenSkeletonCount: 3,
    unseenSkeletonCount: 7,
  };
  assert.equal(windowComparison(fixture, sha)?.unseenSkeletonCount, 7);
  assert.equal(windowComparison(fixture, "b".repeat(64)), null);
  assert.equal(
    windowComparison({ ...fixture, inputAuditPassed: true }, sha),
    null,
    "an audit cannot pass with overlapping inputs",
  );
  assert.equal(
    windowComparison({ ...fixture, validationImproved: true }, sha),
    null,
    "lower validation scores cannot claim improvement",
  );
  assert.equal(
    windowComparison({ ...fixture, windows: { validation: { microF1: NaN } } }, sha),
    null,
  );
});
