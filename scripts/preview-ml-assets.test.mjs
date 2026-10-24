import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { previewMlAssets } from "./preview-ml-assets.mjs";

test("built ML binaries bypass dynamic compression and WASM has the correct MIME", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "ml-preview-"));
  await mkdir(join(root, "assets"));
  await mkdir(join(root, "models"));
  const data = Buffer.alloc(65536, 27);
  await writeFile(join(root, "assets/ort-wasm-simd-threaded-abc.wasm"), data);
  await writeFile(join(root, "models/resnet1d-v1-00.bin"), data);
  const middleware = previewMlAssets(root);
  const server = createServer((req, res) =>
    middleware(req, res, () => {
      res.writeHead(404).end();
    }),
  );
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    server.closeAllConnections();
    server.close();
    await rm(root, { recursive: true, force: true });
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  for (const [path, mime] of [
    ["/assets/ort-wasm-simd-threaded-abc.wasm", "application/wasm"],
    ["/models/resnet1d-v1-00.bin", "application/octet-stream"],
  ]) {
    const response = await fetch(base + path, { headers: { "Accept-Encoding": "br,gzip" } });
    assert.equal(response.headers.get("content-type"), mime);
    assert.equal(response.headers.get("content-encoding"), null);
    assert.equal(Number(response.headers.get("content-length")), data.length);
    assert.deepEqual(Buffer.from(await response.arrayBuffer()), data);
    const head = await fetch(base + path, { method: "HEAD" });
    assert.equal((await head.arrayBuffer()).byteLength, 0);
  }
  assert.equal((await fetch(base + "/models/%2e%2e/secret.bin")).status, 404);
  assert.equal((await fetch(base + "/models/missing.bin")).status, 404);
  assert.equal((await fetch(base + "/models/resnet1d-v1-00.bin", { method: "POST" })).status, 404);
});
