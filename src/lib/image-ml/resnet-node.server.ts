/**
 * ResNet1D inference in Node — the pipeline worker's runner.
 *
 * The browser runs the same ONNX model in a Web Worker
 * (resnet.worker.ts); this module is the server-side twin so EVERY
 * pipeline entry gets screened during the audit, not only the contracts
 * a user opens in the bytecode tab. It reuses the browser module's
 * manifest validation, sequence preparation and hashing (./resnet.ts)
 * so the two runtimes cannot drift: same manifest, same shard integrity
 * checks, same 16,384-byte L2-normalized input, same thresholds.
 *
 * Server-only by construction (node:fs + a wasm binary read from the
 * onnxruntime-web package) — hence the .server.ts suffix. Client code
 * must never import it; browser flows inject run-resnet-browser.ts
 * through the same ResnetRunner seam instead (analyzeAddress opts).
 *
 * Missing model assets or malformed input resolve to null. Inference
 * errors propagate to the audit attachment, which records an explicit
 * error status without failing the static audit. Failed loads are retryable.
 *
 * The inference session is created once per process (~1s, ~15 MB of
 * shards) and runs are serialized through a queue: the wasm runtime is
 * single-threaded here (numThreads = 1, matching the browser worker),
 * and measured inference is ~0.2–0.5 s per contract, far below the
 * per-entry fetch/analysis cost it rides along with.
 */
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import * as ort from "onnxruntime-web/wasm";
import { sha256, validateManifest, type Manifest } from "./resnet.ts";
import { inferAllBytes } from "./all-bytes.ts";
import type { ResnetResult } from "../audit/resnet-result.ts";

const MANIFEST_FILE = "resnet1d-v1.json";

type SessionCtx = {
  manifest: Manifest;
  session: ort.InferenceSession;
};

/**
 * Where the model files live, in resolution order:
 *   1. an explicit directory (tests, unusual deployments);
 *   2. SMARTKONTRAKT_RESNET_MODEL_DIR;
 *   3. <cwd>/public/models — the repo checkout (the worker runs from
 *      the repo root on the phone and in CI);
 *   4. module-relative ../../../public/models — independent of cwd.
 * An explicit directory (1/2) that does not yield a valid manifest is a
 * configuration error the operator chose: return null rather than
 * silently screening with a different model than configured.
 */
export async function resolveResnetModelDir(explicitDir?: string): Promise<string | null> {
  const candidates: { dir: string; explicit: boolean }[] = [];
  if (explicitDir) candidates.push({ dir: explicitDir, explicit: true });
  const envDir = process.env.SMARTKONTRAKT_RESNET_MODEL_DIR;
  if (envDir) candidates.push({ dir: envDir, explicit: true });
  candidates.push({ dir: path.join(process.cwd(), "public", "models"), explicit: false });
  candidates.push({
    dir: fileURLToPath(new URL("../../../public/models", import.meta.url)),
    explicit: false,
  });
  for (const { dir, explicit } of candidates) {
    try {
      const raw = await readFile(path.join(dir, MANIFEST_FILE), "utf8");
      validateManifest(JSON.parse(raw));
      return dir;
    } catch {
      if (explicit) return null;
    }
  }
  return null;
}

async function loadModelBytes(dir: string, manifest: Manifest): Promise<Uint8Array> {
  const bytes = new Uint8Array(manifest.bytes);
  let offset = 0;
  for (const shard of manifest.shards) {
    const part = await readFile(path.join(dir, shard.file));
    if (part.length !== shard.bytes || (await sha256(part)) !== shard.sha256) {
      throw new Error(`ResNet shard integrity check failed: ${shard.file}`);
    }
    bytes.set(part, offset);
    offset += shard.bytes;
  }
  if ((await sha256(bytes)) !== manifest.sha256) {
    throw new Error("ResNet model integrity check failed.");
  }
  return bytes;
}

const sessionCache = new Map<string, Promise<SessionCtx | null>>();

function getSession(modelDir?: string): Promise<SessionCtx | null> {
  // Keyed by the requested directory: an explicit-dir failure (a test, a
  // misconfigured env var) must not poison the default resolution, and
  // vice versa. Within a key, failures are evicted so repaired model assets can be retried.
  const key = modelDir ?? process.env.SMARTKONTRAKT_RESNET_MODEL_DIR ?? "<default>";
  let pending = sessionCache.get(key);
  if (!pending) {
    pending = (async () => {
      try {
        const dir = await resolveResnetModelDir(modelDir);
        if (!dir) return null;
        const manifest = validateManifest(
          JSON.parse(await readFile(path.join(dir, MANIFEST_FILE), "utf8")),
        );
        const bytes = await loadModelBytes(dir, manifest);
        // The wasm binary ships inside the onnxruntime-web package; read
        // it from disk (the browser worker gets it by URL instead).
        // Prefer resolving the installed package; fall back to the
        // repo-layout path if the package's exports map hides its root.
        let wasmPath: string;
        try {
          const require = createRequire(import.meta.url);
          const pkgMain = require.resolve("onnxruntime-web");
          wasmPath = path.join(
            path.dirname(path.dirname(pkgMain)),
            "dist",
            "ort-wasm-simd-threaded.wasm",
          );
        } catch {
          wasmPath = fileURLToPath(
            new URL(
              "../../../node_modules/onnxruntime-web/dist/ort-wasm-simd-threaded.wasm",
              import.meta.url,
            ),
          );
        }
        ort.env.wasm.numThreads = 1;
        ort.env.wasm.proxy = false;
        ort.env.wasm.wasmBinary = await readFile(wasmPath);
        const session = await ort.InferenceSession.create(bytes, {
          executionProviders: ["wasm"],
        });
        return { manifest, session };
      } catch {
        return null;
      }
    })();
    sessionCache.set(key, pending);
    void pending.then(ctx => { if (!ctx) sessionCache.delete(key); }, () => sessionCache.delete(key));
  }
  return pending;
}

// Serialize session.run calls — one shared session, single-thread wasm.
let runQueue: Promise<unknown> = Promise.resolve();

/**
 * Run ResNet1D over runtime bytecode. Returns the shared ResnetResult
 * shape (audit/resnet-result.ts), or null when the model is unavailable
 * or the input is not classifiable bytecode (empty / malformed hex).
 * Every consecutive window is processed; there is no prefix or size cap.
 */
export async function runResnetNode(
  bytecode: string,
  opts?: { modelDir?: string },
): Promise<ResnetResult | null> {
  const run = runQueue.then(async () => {
    const hex = bytecode.trim().replace(/^0x/i, "");
    if (!hex || hex.length % 2 || !/^[a-f0-9]+$/i.test(hex)) return null;
    try {
      const ctx = await getSession(opts?.modelDir);
      if (!ctx) return null;
      return await inferAllBytes(bytecode, async sequence => {
        const input = new ort.Tensor("float32", sequence, [1, 1, 16384]);
        let output: Record<string, ort.Tensor> | undefined;
        try {
          output = await ctx.session.run({bytecode: input});
          return Array.from(output.probabilities.data as Float32Array);
        } finally {
          input.dispose();
          if (output) for (const tensor of Object.values(output)) tensor.dispose();
        }
      }, ctx.manifest);
    } catch (error) {
      sessionCache.clear();
      throw error;
    }
  });
  runQueue = run.catch(() => undefined);
  return run;
}
