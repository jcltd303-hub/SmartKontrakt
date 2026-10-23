import { test } from "node:test";
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const FIXTURES = fileURLToPath(new URL("../foundry/poc-fixtures/", import.meta.url));

test("the fixture project is a runnable Foundry project", async () => {
  const entries = await readdir(FIXTURES);
  assert.ok(entries.includes("foundry.toml"), "fixtures need a foundry.toml");
  assert.ok(entries.includes("src"), "fixtures need src/");
  assert.ok(entries.includes("test"), "fixtures need test/");
  const tests = (await readdir(join(FIXTURES, "test"))).filter((f) => f.endsWith(".t.sol"));
  assert.ok(tests.length >= 1, "at least one fixture test");
});

test("every fixture is differential: reproduce, and do NOT reproduce when fixed", async () => {
  const tests = (await readdir(join(FIXTURES, "test"))).filter((f) => f.endsWith(".t.sol"));
  for (const file of tests) {
    const src = await readFile(join(FIXTURES, "test", file), "utf8");
    assert.match(src, /import \{Test, console\} from "forge-std\/Test\.sol";/, `${file}: forge-std import`);
    assert.match(src, /test_fixtureReproduces/, `${file}: missing the reproduction half`);
    assert.match(src, /test_fixtureDoesNotReproduce/, `${file}: missing the precision half`);
    // Both halves must make a real assertion — not just call the contract.
    const assertions = src.match(/assert(?:Eq|Gt|Lt|Ge|Le|True|False|NotEq)\(/g) ?? [];
    assert.ok(assertions.length >= 2, `${file}: needs assertions in both halves`);
    assert.match(src, /vm\.prank|vm\.startPrank/, `${file}: the exploit must be driven by a distinct actor`);
  }
});

test("every fixture port carries provenance and preserves the vulnerable ordering", async () => {
  const srcDir = join(FIXTURES, "src");
  const files = (await readdir(srcDir)).filter((f) => f.endsWith(".sol") && !/Fixed\.sol$/.test(f));
  assert.ok(files.length >= 1, "at least one vulnerable port");
  for (const file of files) {
    const src = await readFile(join(srcDir, file), "utf8");
    assert.match(src, /PROVENANCE/, `${file}: no provenance header`);
    // Two honest provenance kinds. Dataset ports name the dataset and
    // the dataset path. MODELLED ports (for templates whose index.json
    // provenance is "modelled" — no SmartBugs source exists for them)
    // must say so explicitly and name the fallback template they port;
    // claiming a dataset path for one would fabricate the grounding
    // this test exists to protect. (Added with the TokenRescue port —
    // template 46-token-rescue is modelled, so its port is too.)
    const isDatasetPort =
      /smartbugs\/smartbugs-curated/.test(src) && /dataset\/[a-z_]+\/[A-Za-z0-9_]+\.sol/.test(src);
    const isModelledPort =
      /Modelled:\s+no dataset source/.test(src) &&
      /poc-fallbacks\/\d+-[a-z0-9-]+\.t\.sol/.test(src) &&
      !/dataset\/[a-z_]+\/[A-Za-z0-9_]+\.sol/.test(src);
    assert.ok(
      isDatasetPort || isModelledPort,
      `${file}: provenance must name the dataset + dataset path, or declare itself modelled and name its fallback template`,
    );
    assert.match(src, /pragma solidity \^?0\.8/, `${file}: ports must be migrated to >= 0.8`);
  }
});

test("every dataset contract a template claims has a fixture port", async () => {
  // The coverage guarantee: if a template says it derives from a SmartBugs
  // contract, a port of that contract must exist. This is what keeps the
  // "grounded in real code" claim honest as templates are added.
  const { POC_FALLBACK_CATALOG } = await import("../src/lib/audit/poc-fallbacks.ts");
  const claimed = new Set();
  for (const entry of POC_FALLBACK_CATALOG) {
    if (entry.provenance.kind === "dataset") {
      for (const source of entry.provenance.sources) claimed.add(source);
    }
  }
  assert.ok(claimed.size >= 20, `expected many claimed dataset contracts, got ${claimed.size}`);

  const srcDir = join(FIXTURES, "src");
  const declared = new Set();
  for (const file of (await readdir(srcDir)).filter((f) => f.endsWith(".sol") && !/Fixed\.sol$/.test(f))) {
    const src = await readFile(join(srcDir, file), "utf8");
    for (const m of src.matchAll(/dataset\/[a-z_]+\/[A-Za-z0-9_]+\.sol/g)) declared.add(m[0]);
  }

  // provenance records `<category>/<file>.sol`; the port headers record the full
  // `dataset/<category>/<file>.sol` path. Normalise before comparing.
  const missing = [...claimed].filter((s) => !declared.has(`dataset/${s}`)).sort();
  assert.deepEqual(missing, [], `no fixture port for: ${missing.join(", ")}`);
});

test("every dataset-backed template names a real dataset contract", async () => {
  const { POC_FALLBACK_CATALOG } = await import("../src/lib/audit/poc-fallbacks.ts");
  const datasetBacked = POC_FALLBACK_CATALOG.filter((e) => e.provenance.kind === "dataset");
  assert.ok(datasetBacked.length >= 20, "most templates should trace to a dataset contract");
  for (const entry of POC_FALLBACK_CATALOG) {
    const p = entry.provenance;
    assert.ok(p && typeof p.kind === "string", `${entry.file}: no provenance`);
    assert.ok(["dataset", "modelled"].includes(p.kind), `${entry.file}: bad provenance kind`);
    assert.ok(typeof p.category === "string" && p.category.length > 0, `${entry.file}: no category`);
    if (p.kind === "dataset") {
      assert.ok(p.sources.length > 0, `${entry.file}: dataset provenance with no source`);
      for (const s of p.sources) {
        assert.match(s, /^[a-z_]+\/[A-Za-z0-9_]+\.sol$/, `${entry.file}: "${s}" is not a dataset path`);
      }
    } else {
      assert.ok(p.note, `${entry.file}: a modelled template must say why it has no dataset source`);
    }
  }
});
