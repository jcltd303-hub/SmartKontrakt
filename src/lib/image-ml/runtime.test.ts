import { test } from "node:test";
import assert from "node:assert/strict";
import {
  averagePool,
  CLASSES,
  convRelu,
  ENCODING,
  MAX_BYTECODE_BYTES,
  predict,
  prepareBytecode,
  validateModel,
} from "./runtime.ts";
function fixture() {
  const channels = [3, 8, 16, 24];
  return {
    schemaVersion: 1,
    modelId: "fixture",
    architecture: "rgb-cnn-64-v1",
    classes: [...CLASSES],
    input: { size: 64, encoding: ENCODING, normalization: "0..1" },
    layers: [0, 1, 2].map((i) => ({
      kind: "conv2d",
      inChannels: channels[i],
      outChannels: channels[i + 1],
      kernel: 3,
      stride: 2,
      padding: 1,
      weight: Array(channels[i] * channels[i + 1] * 9).fill(0),
      bias: Array(channels[i + 1]).fill(0),
    })),
    pool: { kind: "avg", kernel: 2, stride: 2 },
    linear: {
      inFeatures: 384,
      outFeatures: 5,
      weight: Array(1920).fill(0),
      bias: [0, 1, -1, 2, -2],
    },
    thresholds: [0.5, 0.5, 0.5, 0.5, 0.5],
    training: { source: "fixture" },
    evaluation: { source: "fixture" },
  };
}
test("strict bounded hex accepts optional prefix and rejects source and partial bytes", () => {
  for (const s of [
    "",
    "0x",
    "0x1",
    "pragma solidity",
    "00 zz",
    "0xgg",
    "0".repeat(MAX_BYTECODE_BYTES * 2 + 2),
  ])
    assert.throws(() => prepareBytecode(s));
  assert.equal(prepareBytecode(" 0Xff00 ").bytes, 2);
});
test("RGB triples retain channel order, pad square, and resize by nearest center", () => {
  const p = prepareBytecode("ff000000ff00");
  assert.equal(p.side, 2);
  assert.deepEqual([...p.square], [255, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual([...p.rgb.slice(0, 3)], [255, 0, 0]);
  assert.deepEqual([...p.rgb.slice(32 * 3, 32 * 3 + 3)], [0, 255, 0]);
  assert.equal(p.input[0], 1);
  assert.equal(p.input[4096 + 32], 1);
  assert.equal(p.input[4096], 0);
  assert.equal(p.input[63 * 64 + 63], 0);
});
test("convolution uses OIHW order, zero padding, stride and ReLU", () => {
  const result = convRelu(new Float32Array([1, 2, 3, 4, 5, 6, 7, 8, 9]), 3, {
    kind: "conv2d",
    inChannels: 1,
    outChannels: 2,
    kernel: 3,
    stride: 2,
    padding: 1,
    weight: [...Array(9).fill(1), ...Array(9).fill(-1)],
    bias: [1, 1],
  });
  assert.equal(result.side, 2);
  assert.deepEqual([...result.data], [13, 17, 25, 29, 0, 0, 0, 0]);
});
test("average pooling preserves NCHW channel blocks", () => {
  assert.deepEqual([...averagePool(new Float32Array([1, 2, 3, 4, 5, 6, 7, 8]), 2, 2)], [2.5, 6.5]);
});
test("complete model produces independent sigmoid scores from linear biases", () => {
  const model = validateModel(fixture());
  const scores = predict(model, prepareBytecode("ff0000").input);
  assert.equal(scores[0].score, 0.5);
  assert.equal(scores[0].flagged, true);
  assert.ok(Math.abs(scores[1].score - 1 / (1 + Math.exp(-1))) < 1e-10);
  assert.ok(scores[2].score < 0.5);
});
test("schema rejects wrong class order, dimensions, thresholds and nonfinite weights", () => {
  for (const mutate of [
    (m: ReturnType<typeof fixture>) => m.classes.reverse(),
    (m: ReturnType<typeof fixture>) => m.layers[0].weight.pop(),
    (m: ReturnType<typeof fixture>) => (m.thresholds[0] = 1.1),
    (m: ReturnType<typeof fixture>) => (m.linear.bias[0] = NaN),
    (m: ReturnType<typeof fixture>) => (m.input.encoding = "other"),
  ]) {
    const m = fixture();
    mutate(m);
    assert.throws(() => validateModel(m));
  }
});
