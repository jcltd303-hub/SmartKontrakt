/**
 * runResnetBrowser — the browser twin of resnet-node.server.ts.
 *
 * App-side audit flows (batch pipeline, single-address fetch, pasted
 * bytecode) run IN the browser, where the Node runner cannot exist.
 * They inject this runner into analyzeAddress / attachResnetToReport
 * instead, so those entries get the same screening, the same shared
 * ResnetResult shape and the same bounded score term as worker
 * entries. It drives the exact worker the Image ML panel uses
 * (resnet.worker.ts) — one model, one manifest, one set of thresholds.
 *
 * A fresh worker is spawned per call and terminated after: the panel's
 * lifecycle is per-run too, and audit flows are user-paced (the batch
 * pipeline analyzes sequentially), so the ~1–2 s model load per entry
 * is acceptable and keeps zero shared worker state to corrupt.
 *
 * Fail-soft like every runner: no Worker support, a worker error, an
 * invalid model reply, or the timeout all resolve null ("not run").
 */
import { previewPathPrefix } from "../preview-path-prefix.ts";
import type { ResnetResult } from "../audit/resnet-result.ts";

type WorkerReply =
  | {
      ok: true;
      modelId: string;
      architecture: string;
      checkpointSha256: string;
      predictions: ResnetResult["predictions"];
    }
  | { ok: false; error: string };

const RUN_TIMEOUT_MS = 120_000;

export function runResnetBrowser(bytecode: string): Promise<ResnetResult | null> {
  return new Promise((resolve) => {
    let worker: Worker | null = null;
    let settled = false;
    const finish = (value: ResnetResult | null) => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timer);
      try {
        worker?.terminate();
      } catch {
        // already gone
      }
      resolve(value);
    };
    const timer = window.setTimeout(() => finish(null), RUN_TIMEOUT_MS);
    try {
      worker = new Worker(new URL("./resnet.worker.ts", import.meta.url), { type: "module" });
      worker.onmessage = (event: MessageEvent<WorkerReply>) => {
        const data = event.data;
        if (!data || data.ok !== true) return finish(null);
        try {
          const hex = bytecode.trim().replace(/^0x/i, "");
          const inputBytes = Math.floor(hex.length / 2);
          finish({
            modelId: data.modelId,
            architecture: data.architecture,
            checkpointSha256: data.checkpointSha256,
            predictions: data.predictions,
            inputBytes,
            truncated: inputBytes > 16384,
            ranAt: new Date().toISOString(),
          });
        } catch {
          finish(null);
        }
      };
      worker.onerror = () => finish(null);
      const prefix = previewPathPrefix(window.location.hostname, window.location.pathname) ?? "";
      worker.postMessage({
        bytecode,
        modelUrl: new URL(`${prefix}/models/resnet1d-v1.json`, window.location.origin).href,
      });
    } catch {
      finish(null);
    }
  });
}
