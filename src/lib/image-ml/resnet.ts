import { CLASSES, MAX_BYTECODE_BYTES } from "./runtime.ts";
export function prepareSequence(value: string): Float32Array {
  const hex = value.trim().replace(/^0x/i, "");
  if (!hex || hex.length % 2 || !/^[\da-f]+$/i.test(hex) || hex.length > MAX_BYTECODE_BYTES * 2)
    throw new Error("ResNet requires complete hexadecimal bytecode, at most 128 KiB.");
  const values = new Float32Array(16384);
  let squares = 0;
  for (let i = 0; i < Math.min(hex.length / 2, values.length); i++) {
    values[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    squares += values[i] * values[i];
  }
  const norm = Math.sqrt(squares);
  if (norm) for (let i = 0; i < values.length; i++) values[i] /= norm;
  return values;
}
export type Manifest = {
  schemaVersion: 1;
  modelId: string;
  architecture: string;
  sequenceLength: number;
  normalization: string;
  classes: string[];
  thresholds: number[];
  bytes: number;
  sha256: string;
  checkpointSha256: string;
  shards: { file: string; bytes: number; sha256: string }[];
  training: Record<string, unknown>;
  evaluation: Record<string, unknown>;
};
const record = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
const hash = (v: unknown): v is string => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
export function validateManifest(value: unknown): Manifest {
  const fail = () => {
    throw new Error("Invalid ResNet model manifest.");
  };
  if (!record(value)) return fail();
  const m = value;
  if (
    m.schemaVersion !== 1 ||
    m.architecture !== "upstream-resnet1d-16384-v1" ||
    m.sequenceLength !== 16384 ||
    m.normalization !== "per-example L2 after zero-pad/truncate" ||
    typeof m.modelId !== "string" ||
    m.modelId.length > 160 ||
    !m.modelId.length ||
    JSON.stringify(m.classes) !== JSON.stringify(CLASSES) ||
    !Array.isArray(m.thresholds) ||
    m.thresholds.length !== 5 ||
    !m.thresholds.every((v) => typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1) ||
    !hash(m.sha256) ||
    !hash(m.checkpointSha256) ||
    !Number.isSafeInteger(m.bytes) ||
    (m.bytes as number) < 1 ||
    (m.bytes as number) > 20 * 1024 * 1024 ||
    !Array.isArray(m.shards) ||
    !m.shards.length ||
    m.shards.length > 20 ||
    !record(m.training) ||
    !record(m.evaluation)
  )
    return fail();
  let total = 0;
  const names = new Set();
  for (const shard of m.shards) {
    if (
      !record(shard) ||
      typeof shard.file !== "string" ||
      !/^resnet1d-v1-\d{2}\.bin$/.test(shard.file) ||
      names.has(shard.file) ||
      !Number.isSafeInteger(shard.bytes) ||
      (shard.bytes as number) < 1 ||
      (shard.bytes as number) > 1024 * 1024 ||
      !hash(shard.sha256)
    )
      return fail();
    names.add(shard.file);
    total += shard.bytes as number;
  }
  if (total !== m.bytes) return fail();
  return m as Manifest;
}
export async function sha256(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>);
  return Array.from(new Uint8Array(digest), (v) => v.toString(16).padStart(2, "0")).join("");
}
export async function download(url: string, limit: number): Promise<Uint8Array> {
  const response = await fetch(url, {
    credentials: "omit",
    redirect: "error",
    signal: AbortSignal.timeout(60000),
  });
  if (!response.ok || !response.body) throw new Error("Model download unavailable.");
  if (Number(response.headers.get("content-length")) > limit)
    throw new Error("Model exceeds download limit.");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > limit) throw new Error("Model exceeds download limit.");
      chunks.push(value);
    }
  } finally {
    await reader.cancel();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}
export async function loadResnet(url: string) {
  const manifest = validateManifest(
    JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await download(url, 64 * 1024))),
  );
  const bytes = new Uint8Array(manifest.bytes);
  const offsets: number[] = [];
  let offset = 0;
  for (const shard of manifest.shards) {
    offsets.push(offset);
    offset += shard.bytes;
  }
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(4, manifest.shards.length) }, async () => {
      while (next < manifest.shards.length) {
        const index = next++;
        const shard = manifest.shards[index];
        const part = await download(new URL(shard.file, url).href, shard.bytes);
        if (part.length !== shard.bytes || (await sha256(part)) !== shard.sha256)
          throw new Error("ResNet model integrity check failed.");
        bytes.set(part, offsets[index]);
      }
    }),
  );
  if ((await sha256(bytes)) !== manifest.sha256)
    throw new Error("ResNet model integrity check failed.");
  return { manifest, bytes };
}

/** Model URL carries the public preview prefix; Vite emits root-relative assets. */
export function runtimeAssetUrl(asset: string, manifestUrl: string): string {
  const manifest = new URL(manifestUrl);
  const prefix = manifest.pathname.replace(/\/models\/resnet1d-v1\.json$/, "");
  const target = new URL(asset, manifest.origin);
  if (target.origin !== manifest.origin) throw new Error("Runtime assets must be self-hosted.");
  target.pathname = `${prefix}${target.pathname}`;
  return target.href;
}
