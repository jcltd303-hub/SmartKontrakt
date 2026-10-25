import * as ort from "onnxruntime-web/wasm";
import wasmUrl from "onnxruntime-web/ort-wasm-simd-threaded.wasm?url";
import { download, loadResnet, prepareSequence, runtimeAssetUrl } from "./resnet";
self.onmessage = async (event: MessageEvent<{ bytecode: string; modelUrl: string }>) => {
  const started = performance.now();
  try {
    const input = prepareSequence(event.data.bytecode);
    let modelDownloadMs = 0,
      wasmDownloadMs = 0;
    const [{ manifest, bytes }, wasmBytes] = await Promise.all([
      loadResnet(event.data.modelUrl).then((value) => {
        modelDownloadMs = performance.now() - started;
        return value;
      }),
      download(runtimeAssetUrl(wasmUrl, event.data.modelUrl), 20 * 1024 * 1024).then((value) => {
        wasmDownloadMs = performance.now() - started;
        return value;
      }),
    ]);
    ort.env.wasm.numThreads = 1;
    ort.env.wasm.proxy = false;
    // Explicit bounded bytes avoid MIME-dependent streaming/fallback downloads.
    // The /wasm bundled entry already contains its matching Emscripten factory.
    ort.env.wasm.wasmBinary = wasmBytes;
    const sessionStarted = performance.now();
    const session = await ort.InferenceSession.create(bytes, { executionProviders: ["wasm"] });
    const loaded = performance.now();
    try {
      const output = await session.run({
        bytecode: new ort.Tensor("float32", input, [1, 1, 16384]),
      });
      const scores = Array.from(output.probabilities.data as Float32Array);
      if (scores.length !== 5 || !scores.every((v) => Number.isFinite(v) && v >= 0 && v <= 1))
        throw new Error("Invalid ResNet output.");
      self.postMessage({
        ok: true,
        modelId: manifest.modelId,
        training: manifest.training,
        evaluation: manifest.evaluation,
        timing: {
          loadMs: loaded - started,
          inferenceMs: performance.now() - loaded,
          modelDownloadMs,
          wasmDownloadMs,
          sessionMs: loaded - sessionStarted,
        },
        predictions: manifest.classes.map((label, i) => ({
          label,
          score: scores[i],
          threshold: manifest.thresholds[i],
          flagged: scores[i] >= manifest.thresholds[i],
        })),
      });
    } finally {
      await session.release();
    }
  } catch (error) {
    self.postMessage({
      ok: false,
      error: error instanceof Error ? error.message : "ResNet could not run.",
    });
  }
};
