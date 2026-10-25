import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runResnetNode, resolveResnetModelDir } from "./resnet-node.server.ts";

/**
 * The Node runner is the worker's half of resnet coverage: it must run
 * the REAL model (the same sharded ONNX graph the browser worker runs)
 * and reproduce the published parity fixtures, or the scores it folds
 * into the archive are fiction. These tests load the actual model from
 * public/models/ — a few seconds, once per process (session cached).
 */

const modelsDir = new URL("../../../public/models/", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("resnet1d-v1.json", modelsDir), "utf8")) as {
  modelId: string;
  architecture: string;
  checkpointSha256: string;
  classes: string[];
  thresholds: number[];
};
const parity = JSON.parse(readFileSync(new URL("resnet1d-parity.json", modelsDir), "utf8")) as {
  cases: { bytecode: string; probabilities: number[] }[];
};

test("node runner reproduces the published parity fixtures", async () => {
  assert.ok(parity.cases.length >= 3, "parity corpus present");
  for (const [i, c] of parity.cases.entries()) {
    const result = await runResnetNode(c.bytecode);
    assert.ok(result, `case ${i}: runner returned a result`);
    assert.equal(result.modelId, manifest.modelId);
    assert.equal(result.architecture, manifest.architecture);
    assert.equal(result.checkpointSha256, manifest.checkpointSha256);
    assert.equal(result.predictions.length, manifest.classes.length);
    for (const [j, p] of result.predictions.entries()) {
      assert.equal(p.label, manifest.classes[j], `case ${i} class ${j} label`);
      assert.equal(p.threshold, manifest.thresholds[j], `case ${i} class ${j} threshold`);
      assert.ok(
        Math.abs(p.score - c.probabilities[j]) <= 1e-4,
        `case ${i} class ${j}: score ${p.score} vs fixture ${c.probabilities[j]}`,
      );
      assert.equal(p.flagged, p.score >= p.threshold, `case ${i} class ${j} flag consistency`);
    }
    const bytes = Math.floor(c.bytecode.replace(/^0x/i, "").length / 2);
    assert.equal(result.inputBytes, bytes);
    assert.equal(result.truncated, bytes > 16384);
  }
});

test("unclassifiable input resolves null, never a throw", async () => {
  assert.equal(await runResnetNode(""), null);
  assert.equal(await runResnetNode("0x"), null);
  assert.equal(await runResnetNode("not-hex"), null);
  assert.equal(await runResnetNode(`0x${"ab".repeat(128 * 1024 + 1)}`), null, "over the 128 KiB cap");
});

test("an explicit model dir that does not hold the model resolves null (no silent fallback)", async () => {
  assert.equal(await resolveResnetModelDir("/nonexistent/resnet-models"), null);
  assert.equal(await runResnetNode(parity.cases[0].bytecode, { modelDir: "/nonexistent/resnet-models" }), null);
  // …and the default resolution still finds the repo's model afterwards
  // (the failure is cached under its own key, not the default's).
  const dir = await resolveResnetModelDir();
  assert.ok(dir && dir.endsWith("public/models"), `default dir resolves: ${dir}`);
});
