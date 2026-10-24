import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { predict, prepareBytecode, validateModel } from "./runtime.ts";

const modelArtifact = JSON.parse(
  readFileSync(new URL("../../../public/models/bytecode-image-v1.json", import.meta.url), "utf8"),
);
const parityArtifact: { cases: { bytecode: string; probabilities: number[] }[] } = JSON.parse(
  readFileSync(
    new URL("../../../public/models/bytecode-image-v1-parity.json", import.meta.url),
    "utf8",
  ),
);

test("shipped trained CNN matches independent PyTorch predictions within 1e-5", () => {
  const model = validateModel(modelArtifact);
  assert.deepEqual(model.classes, [
    "access-control",
    "arithmetic",
    "reentrancy",
    "unchecked-calls",
    "others",
  ]);
  assert.deepEqual(
    model.thresholds,
    [
      0.5250000000000001, 0.4250000000000001, 0.4000000000000001, 0.4250000000000001,
      0.47500000000000014,
    ],
  );
  assert.ok(
    parityArtifact.cases.length >= 5,
    "parity must include at least five real bytecode cases",
  );
  for (const [caseIndex, fixture] of parityArtifact.cases.entries()) {
    assert.equal(fixture.probabilities.length, 5);
    const predictions = predict(model, prepareBytecode(fixture.bytecode).input);
    assert.deepEqual(
      predictions.map((p) => p.label),
      model.classes,
    );
    assert.deepEqual(
      predictions.map((p) => p.threshold),
      model.thresholds,
    );
    for (let i = 0; i < 5; i++) {
      assert.ok(Number.isFinite(fixture.probabilities[i]));
      const error = Math.abs(predictions[i].score - fixture.probabilities[i]);
      assert.ok(
        error <= 1e-5,
        `case ${caseIndex}, ${model.classes[i]}: TS ${predictions[i].score}, Torch ${fixture.probabilities[i]}, error ${error}`,
      );
      assert.equal(predictions[i].flagged, fixture.probabilities[i] >= model.thresholds[i]);
    }
  }
});
