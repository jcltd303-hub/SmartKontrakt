import * as ort from "onnxruntime-web/wasm";
import wasmUrl from "onnxruntime-web/ort-wasm-simd-threaded.wasm?url";
import mjsUrl from "onnxruntime-web/ort-wasm-simd-threaded.mjs?url";
import { loadResnet, prepareSequence, runtimeAssetUrl } from "./resnet";
self.onmessage = async (event: MessageEvent<{ bytecode: string; modelUrl: string }>) => {
  const started = performance.now();
  try {
    const input = prepareSequence(event.data.bytecode);
    const { manifest, bytes } = await loadResnet(event.data.modelUrl);
    ort.env.wasm.numThreads = 1;
    ort.env.wasm.proxy = false;
    ort.env.wasm.wasmPaths = {
      wasm: runtimeAssetUrl(wasmUrl, event.data.modelUrl),
      mjs: runtimeAssetUrl(mjsUrl, event.data.modelUrl),
    };
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
        timing: { loadMs: loaded - started, inferenceMs: performance.now() - loaded },
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
