/** Exact byte-image encoding shared with the training pipeline. Raw metadata is retained. */
export const MAX_BYTECODE_BYTES = 128 * 1024;
export const CLASSES = [
  "access-control",
  "arithmetic",
  "reentrancy",
  "unchecked-calls",
  "others",
] as const;
export const ENCODING = "rgb-triplets-square-zero-pad-nearest-center-v1";
export function prepareBytecode(value: string) {
  const hex = value.trim().replace(/^0x/i, "");
  if (!hex) throw new Error("Paste non-empty EVM bytecode to use Image ML.");
  if (hex.length > MAX_BYTECODE_BYTES * 2)
    throw new Error("Image ML accepts at most 128 KiB of raw bytecode.");
  if (!/^[\da-f]+$/i.test(hex))
    throw new Error(
      "Image ML requires raw hexadecimal bytecode, not Solidity source or other text.",
    );
  if (hex.length % 2)
    throw new Error("Bytecode must contain complete pairs of hexadecimal digits.");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  const side = Math.ceil(Math.sqrt(Math.ceil(bytes.length / 3)));
  const square = new Uint8Array(side * side * 3);
  square.set(bytes);
  const rgb = new Uint8ClampedArray(64 * 64 * 3);
  const input = new Float32Array(3 * 64 * 64);
  for (let y = 0; y < 64; y++)
    for (let x = 0; x < 64; x++) {
      const sy = Math.min(side - 1, Math.floor(((y + 0.5) * side) / 64));
      const sx = Math.min(side - 1, Math.floor(((x + 0.5) * side) / 64));
      for (let c = 0; c < 3; c++) {
        const v = square[(sy * side + sx) * 3 + c];
        rgb[(y * 64 + x) * 3 + c] = v;
        input[c * 4096 + y * 64 + x] = v / 255;
      }
    }
  return { bytes: bytes.length, side, square, rgb, input };
}
export type Conv = {
  kind: "conv2d";
  inChannels: number;
  outChannels: number;
  kernel: number;
  stride: number;
  padding: number;
  weight: number[];
  bias: number[];
};
export type Model = {
  schemaVersion: 1;
  modelId: string;
  architecture: "rgb-cnn-64-v1";
  classes: string[];
  input: { size: number; encoding: string; normalization: string };
  layers: Conv[];
  pool: { kind: string; kernel: number; stride: number };
  linear: { inFeatures: number; outFeatures: number; weight: number[]; bias: number[] };
  thresholds: number[];
  training: Record<string, unknown>;
  evaluation: Record<string, unknown>;
};
function record(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}
function numbers(v: unknown, count: number): v is number[] {
  return (
    Array.isArray(v) &&
    v.length === count &&
    v.every((n) => typeof n === "number" && Number.isFinite(n) && Math.abs(n) <= 1e6)
  );
}
export function validateModel(value: unknown): Model {
  const fail = () => {
    throw new Error("Image ML model is unavailable: unsupported or malformed model artifact.");
  };
  if (!record(value)) return fail();
  const m = value;
  if (
    m.schemaVersion !== 1 ||
    typeof m.modelId !== "string" ||
    !m.modelId.length ||
    m.modelId.length > 160 ||
    m.architecture !== "rgb-cnn-64-v1" ||
    JSON.stringify(m.classes) !== JSON.stringify(CLASSES)
  )
    return fail();
  if (
    !record(m.input) ||
    m.input.size !== 64 ||
    m.input.encoding !== ENCODING ||
    m.input.normalization !== "0..1"
  )
    return fail();
  if (!Array.isArray(m.layers) || m.layers.length !== 3) return fail();
  const channels = [3, 8, 16, 24];
  for (let i = 0; i < 3; i++) {
    const l = m.layers[i];
    if (
      !record(l) ||
      l.kind !== "conv2d" ||
      l.inChannels !== channels[i] ||
      l.outChannels !== channels[i + 1] ||
      l.kernel !== 3 ||
      l.stride !== 2 ||
      l.padding !== 1 ||
      !numbers(l.weight, channels[i] * channels[i + 1] * 9) ||
      !numbers(l.bias, channels[i + 1])
    )
      return fail();
  }
  if (!record(m.pool) || m.pool.kind !== "avg" || m.pool.kernel !== 2 || m.pool.stride !== 2)
    return fail();
  if (
    !record(m.linear) ||
    m.linear.inFeatures !== 384 ||
    m.linear.outFeatures !== 5 ||
    !numbers(m.linear.weight, 1920) ||
    !numbers(m.linear.bias, 5)
  )
    return fail();
  if (
    !numbers(m.thresholds, 5) ||
    m.thresholds.some((t) => t < 0 || t > 1) ||
    !record(m.training) ||
    !record(m.evaluation) ||
    !Object.keys(m.training).length ||
    !Object.keys(m.evaluation).length
  )
    return fail();
  return m as Model;
}
export function convRelu(input: Float32Array, side: number, l: Conv) {
  const outSide = Math.floor((side + 2 * l.padding - l.kernel) / l.stride) + 1;
  const out = new Float32Array(l.outChannels * outSide * outSide);
  for (let o = 0; o < l.outChannels; o++)
    for (let y = 0; y < outSide; y++)
      for (let x = 0; x < outSide; x++) {
        let sum = l.bias[o];
        for (let c = 0; c < l.inChannels; c++)
          for (let ky = 0; ky < l.kernel; ky++)
            for (let kx = 0; kx < l.kernel; kx++) {
              const sy = y * l.stride + ky - l.padding,
                sx = x * l.stride + kx - l.padding;
              if (sy >= 0 && sy < side && sx >= 0 && sx < side)
                sum +=
                  input[c * side * side + sy * side + sx] *
                  l.weight[((o * l.inChannels + c) * l.kernel + ky) * l.kernel + kx];
            }
        out[o * outSide * outSide + y * outSide + x] = Math.max(0, sum);
      }
  return { data: out, side: outSide };
}
export function averagePool(input: Float32Array, side: number, channels: number) {
  const n = side / 2,
    out = new Float32Array(channels * n * n);
  for (let c = 0; c < channels; c++)
    for (let y = 0; y < n; y++)
      for (let x = 0; x < n; x++) {
        const p = c * side * side + y * 2 * side + x * 2;
        out[c * n * n + y * n + x] =
          (input[p] + input[p + 1] + input[p + side] + input[p + side + 1]) / 4;
      }
  return out;
}
export function predict(model: Model, input: Float32Array) {
  if (input.length !== 12288 || input.some((v) => !Number.isFinite(v) || v < 0 || v > 1))
    throw new Error("Invalid image tensor.");
  let data = input,
    side = 64;
  for (const l of model.layers) {
    const next = convRelu(data, side, l);
    data = next.data;
    side = next.side;
  }
  data = averagePool(data, side, 24);
  return model.classes.map((label, i) => {
    let logit = model.linear.bias[i];
    for (let j = 0; j < data.length; j++)
      logit += data[j] * model.linear.weight[i * data.length + j];
    if (!Number.isFinite(logit)) throw new Error("Model produced a non-finite output.");
    const score = 1 / (1 + Math.exp(-logit));
    return { label, score, threshold: model.thresholds[i], flagged: score >= model.thresholds[i] };
  });
}
