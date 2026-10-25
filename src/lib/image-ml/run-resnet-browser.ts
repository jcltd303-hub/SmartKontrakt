/** Shared, serialized audit worker: model and WASM assets load once per worker. */
import { previewPathPrefix } from "../preview-path-prefix.ts";
import { parseResnetJson, type ResnetResult } from "../audit/resnet-result.ts";

let worker: Worker | null = null;
let queue: Promise<unknown> = Promise.resolve();
const RUN_TIMEOUT_MS = 120_000;

export function runResnetBrowser(bytecode: string): Promise<ResnetResult | null> {
  const run = queue.then(() => new Promise<ResnetResult | null>((resolve, reject) => {
    if (typeof window === "undefined" || typeof Worker === "undefined") { resolve(null); return; }
    let settled = false;
    const finish = (value: ResnetResult | null, error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error || !value) {
        worker?.terminate();
        worker = null;
      }
      if (error) reject(error); else resolve(value);
    };
    const timer = setTimeout(() => finish(null, new Error("ResNet inference timed out.")), RUN_TIMEOUT_MS);
    try {
      worker ??= new Worker(new URL("./resnet.worker.ts", import.meta.url), {type: "module"});
      worker.onmessage = event => {
        const data = event.data;
        if (!data || data.ok !== true) { finish(null, new Error(data?.error || "ResNet inference failed.")); return; }
        const result = parseResnetJson(JSON.stringify(data.result));
        if (!result) { finish(null, new Error("Invalid ResNet inference response.")); return; }
        finish(result);
      };
      worker.onerror = event => finish(null, new Error(event.message || "ResNet worker failed."));
      const prefix = previewPathPrefix(window.location.hostname, window.location.pathname) ?? "";
      worker.postMessage({bytecode, allBytes: true,
        modelUrl: new URL(`${prefix}/models/resnet1d-v1.json`, window.location.origin).href});
    } catch (error) {
      finish(null, error instanceof Error ? error : new Error(String(error)));
    }
  }));
  queue = run.catch(() => undefined);
  return run;
}
