// src/lib/audit/bundle-scope.test.ts
//
// Bundle-scope regression corpus (improvement #10). The archive's worst
// misattributions came from Sourcify compilation bundles: every file in
// the unit was concatenated and analyzed, so findings belonging to
// test fixtures and sibling contracts landed on the deployed contract.
// Two real bundles, frozen from the vetted pulls that exposed them:
//
// - bundle-erc1967proxy: 0x0c0388e4bbf121a06ea531d2244e93e044964879 —
//   a stock ERC1967Proxy whose bundle carried OpenZeppelin
//   upgrades-core's deliberately unsafe test fixtures; 29 stored
//   criticals, every one a fixture function (vet #1, 2026-11-01).
// - bundle-upgradeability-proxy: 0x64ff535c5570e9349073f38c53ae9d52ac9337bc —
//   a 216-byte UpgradeabilityProxy shell whose bundle's sibling
//   burnerToken.sol supplied phantom mint/burn/transfer findings
//   (vet #2, 2026-11-01).
//
// Each case runs the PRODUCTION scoping (scopeSourcifyFiles — the same
// function fetchSourcifySource calls) and then the production analysis
// entry (analyzeInput with the scoped contract name), and asserts the
// deployed contract's record carries none of the siblings' findings.
import assert from "node:assert/strict";
import test from "node:test";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scopeSourcifyFiles } from "./address-fetcher.ts";
import { analyzeInput } from "./engine.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));

async function loadBundle(dir: string): Promise<{ name: string; content: string }[]> {
  const root = path.join(HERE, "fixtures", dir);
  const out: { name: string; content: string }[] = [];
  const walk = async (rel: string): Promise<void> => {
    for (const entry of await readdir(path.join(root, rel), { withFileTypes: true })) {
      const childRel = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) await walk(childRel);
      else if (entry.name.endsWith(".sol")) {
        out.push({ name: childRel, content: await readFile(path.join(root, childRel), "utf8") });
      }
    }
  };
  await walk("");
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

test("ERC1967Proxy bundle: scoping excludes the unsafe test fixtures", async () => {
  const files = await loadBundle("bundle-erc1967proxy");
  assert.ok(files.length >= 10, `fixture bundle loaded (${files.length} files)`);
  const scoped = scopeSourcifyFiles(
    files,
    "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy",
  );
  assert.ok(scoped);
  assert.equal(scoped.contractName, "ERC1967Proxy");
  assert.match(scoped.source, /contract ERC1967Proxy/);
  // The fixtures are IN the bundle the test loaded — and OUT of the scope.
  assert.ok(files.some((f) => f.content.includes("extremelyUnsafe")), "fixture sanity: the dangerous file is present in the bundle");
  assert.ok(!scoped.source.includes("extremelyUnsafe"), "the fixture's functions must not reach the analysis");
  assert.ok(!scoped.source.includes("HasSelfDestructNatspec"), "the natspec fixtures must not reach the analysis");

  const report = analyzeInput(scoped.source, "ERC1967Proxy", scoped.contractName);
  const fixtureFns = new Set([
    "explode",
    "extremelyUnsafe",
    "publicDelegateCall",
    "externalDelegateCall",
    "internalDelegateCall",
    "privateDelegateCall",
    "_functionDelegateCall",
  ]);
  assert.equal(
    report.findings.filter((f) => f.severity === "critical").length,
    0,
    "the deployed proxy shell earns no criticals",
  );
  assert.deepEqual(
    report.findings.filter((f) => f.locationFn && fixtureFns.has(f.locationFn)),
    [],
    "no finding may be located in a fixture function",
  );
});

test("UpgradeabilityProxy bundle: scoping excludes the sibling BurnerToken", async () => {
  const files = await loadBundle("bundle-upgradeability-proxy");
  assert.ok(files.length >= 40, `fixture bundle loaded (${files.length} files)`);
  const scoped = scopeSourcifyFiles(files, "UpgradeabilityProxy.sol:UpgradeabilityProxy");
  assert.ok(scoped);
  assert.equal(scoped.contractName, "UpgradeabilityProxy");
  assert.match(scoped.source, /contract UpgradeabilityProxy/);
  assert.ok(files.some((f) => f.content.includes("contract BurnerToken")), "fixture sanity: the sibling token is present in the bundle");
  assert.ok(!scoped.source.includes("contract BurnerToken"), "the sibling token must not reach the analysis");
  // The proxy's own base IS in its import closure — scoping is a closure, not a single file.
  assert.match(scoped.source, /contract BaseUpgradeabilityProxy/);

  const report = analyzeInput(scoped.source, "UpgradeabilityProxy", scoped.contractName);
  assert.equal(
    report.findings.filter((f) => f.severity === "critical").length,
    0,
    "the deployed proxy shell earns no criticals",
  );
});
