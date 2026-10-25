import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { prepareSequence, validateManifest } from "./resnet.ts";

test("ResNet uses padded raw bytes and L2 normalization, truncating at 16384", () => {
  const x = prepareSequence("0x0304");
  assert.equal(x.length, 16384);
  assert.ok(Math.abs(x[0] - 0.6) < 1e-7);
  assert.ok(Math.abs(x[1] - 0.8) < 1e-7);
  assert.equal(x[2], 0);
  assert.ok(prepareSequence("00").every((v) => v === 0));
  assert.deepEqual(prepareSequence("01".repeat(16384) + "ff"), prepareSequence("01".repeat(16384)));
  assert.throws(() => prepareSequence("contract A {}"));
  assert.throws(() => prepareSequence("abc"));
});

test("manifest rejects corrupt lengths, hashes, paths, classes and thresholds", () => {
  const m = JSON.parse(readFileSync("public/models/resnet1d-v1.json", "utf8"));
  assert.equal(validateManifest(m).sequenceLength, 16384);
  for (const change of [
    { bytes: 1 },
    { sha256: "bad" },
    { classes: [] },
    { thresholds: [NaN, 0.5, 0.5, 0.5, 0.5] },
    { shards: [{ ...m.shards[0], file: "../secret" }] },
    { shards: [{ ...m.shards[0], bytes: 10 ** 9 }] },
  ])
    assert.throws(() => validateManifest({ ...m, ...change }));
});

test("runtime assets retain the proxy prefix used by the model manifest", async () => {
  const { runtimeAssetUrl } = await import("./resnet.ts");
  assert.equal(
    runtimeAssetUrl("/assets/ort.wasm", "https://preview.grok.com/hds-abc/models/resnet1d-v1.json"),
    "https://preview.grok.com/hds-abc/assets/ort.wasm",
  );
  assert.equal(
    runtimeAssetUrl("/assets/ort.mjs", "https://app.example/models/resnet1d-v1.json"),
    "https://app.example/assets/ort.mjs",
  );
});

test("model shards download concurrently with a bounded number of active requests", async (t) => {
  const { createServer } = await import("node:http");
  const { loadResnet } = await import("./resnet.ts");
  let active = 0,
    maximum = 0;
  const server = createServer((req, res) => {
    const file = (req.url ?? "").split("/").pop();
    if (!file || !/^resnet1d-v1(?:-\d{2}\.bin|\.json)$/.test(file)) {
      res.writeHead(404).end();
      return;
    }
    active++;
    maximum = Math.max(maximum, active);
    setTimeout(() => {
      res.end(readFileSync(`public/models/${file}`));
      active--;
    }, 30);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => {
    server.closeAllConnections();
    server.close();
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const loaded = await loadResnet(`http://127.0.0.1:${address.port}/models/resnet1d-v1.json`);
  assert.equal(loaded.bytes.length, loaded.manifest.bytes);
  assert.ok(maximum >= 2, "serial downloads delay loading for every shard");
  assert.ok(maximum <= 4, "parallel downloads must keep memory and connections bounded");
});
