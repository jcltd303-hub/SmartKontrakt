import { predict, prepareBytecode, validateModel } from "./runtime";
const MAX_MODEL_BYTES = 2 * 1024 * 1024;
async function loadModel(modelUrl: string) {
  const response = await fetch(modelUrl, { credentials: "omit", redirect: "error" });
  if (!response.ok)
    throw new Error("Image ML model unavailable. The trained artifact could not be loaded.");
  if (Number(response.headers.get("content-length")) > MAX_MODEL_BYTES)
    throw new Error("Model artifact exceeds the download limit.");
  if (!response.body) throw new Error("Model download unavailable.");
  const reader = response.body.getReader(),
    chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_MODEL_BYTES) throw new Error("Model artifact exceeds the download limit.");
      chunks.push(value);
    }
  } finally {
    await reader.cancel();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const c of chunks) {
    bytes.set(c, offset);
    offset += c.length;
  }
  return validateModel(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
}
self.onmessage = async (event: MessageEvent<{ bytecode: string; modelUrl: string }>) => {
  try {
    const image = prepareBytecode(event.data.bytecode);
    const model = await loadModel(event.data.modelUrl);
    const predictions = predict(model, image.input);
    self.postMessage({
      ok: true,
      predictions,
      modelId: model.modelId,
      training: model.training,
      evaluation: model.evaluation,
    });
  } catch (error) {
    self.postMessage({
      ok: false,
      error: error instanceof Error ? error.message : "Image ML could not run.",
    });
  }
};
