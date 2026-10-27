#!/usr/bin/env node
/**
 * Detector binding check — does any test notice when a rule stops emitting?
 *
 * A fixture suite is only worth its weakest binding. A rule can have a fixture
 * that asserts on *something else* and passes forever; a rule can be added with
 * no fixture at all. This script finds both by mutating the analyzer and
 * checking that the corpus goes red.
 *
 * The mutation is deliberately mechanical and honest about what it proves: each
 * detector's emitted id is renamed (`"reentrancy"` -> `"reentrancy::MUTANT"`)
 * in a COPY of `src/lib/audit`, the corpus tests are re-bundled against the
 * copy, and the run is expected to fail. If it passes, no fixture depends on
 * that rule emitting, so the rule is unbound.
 *
 * What it does NOT prove: that the rule's *logic* is right. A rename shows the
 * fixture is wired to the emission, not that the predicate matches the
 * vulnerability. `benchmark-smartbugs.ts` is the measurement for that.
 *
 * Usage:
 *   node scripts/detector-binding-check.mjs                  # every detector
 *   node scripts/detector-binding-check.mjs --only a,b,c     # a subset
 *   node scripts/detector-binding-check.mjs --esbuild <path> # explicit binary
 *   node scripts/detector-binding-check.mjs --json           # machine output
 *
 * esbuild is resolved from node_modules (it ships with vite) or PATH; without
 * it the script exits 2 with a message rather than reporting a false pass.
 */
import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const AUDIT = path.join(ROOT, "src/lib/audit");
const WORK = path.join(ROOT, ".tmp-binding");
/**
 * The behavioural suites the mutation is measured against: every `*.test.ts`
 * in the audit directory EXCEPT the two that are name tables rather than
 * behaviour. `poc-fallbacks.test.ts` asserts that the emitted detector set
 * equals a hand-kept list, so it notices ANY rename and would make every rule
 * look bound; `analyzer-version.test.ts` only checks a version string. The
 * point of this check is whether a FIXTURE depends on the rule emitting.
 */
const EXCLUDED_SUITES = new Set([
  "poc-fallbacks.test.ts",
  "analyzer-version.test.ts",
  "detection-quality.test.ts",
]);

const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : null;
};
const asJson = args.includes("--json");

function findEsbuild() {
  const explicit = flag("esbuild");
  if (explicit) return explicit;
  const local = path.join(ROOT, "node_modules/esbuild/bin/esbuild");
  try {
    readFileSync(local);
    return local;
  } catch {
    /* fall through */
  }
  try {
    execFileSync("esbuild", ["--version"], { stdio: "ignore" });
    return "esbuild";
  } catch {
    return null;
  }
}

function emittedDetectors() {
  const ids = new Set();
  for (const rel of ["detect.ts", "bytecode.ts", "engine.ts"]) {
    const src = readFileSync(path.join(AUDIT, rel), "utf8");
    for (const m of src.matchAll(/detector:\s*"([^"]+)"/g)) ids.add(m[1]);
  }
  ids.add("bytecode-delegatecall");
  ids.add("bytecode-callcode");
  return [...ids].sort();
}

const esbuild = findEsbuild();
if (!esbuild) {
  console.error(
    "detector-binding-check: esbuild not found. Pass --esbuild <path> or install dependencies (vite ships esbuild). Not reporting a result rather than reporting a false pass.",
  );
  process.exit(2);
}

const CORPUS = readdirSync(AUDIT)
  .filter((f) => f.endsWith(".test.ts") && !EXCLUDED_SUITES.has(f))
  .sort();

// Which suites bundle at all in this environment? A suite that imports a server
// module (the database, the react runtime) cannot be bundled here, and letting
// it poison the shared entry would abort every mutation.
const bundleable = new Set();
const unbundleable = new Map();
cpSync(path.join(ROOT, "src/lib"), path.join(WORK, "lib"), { recursive: true });
for (const f of CORPUS) {
  const probe = spawnSync(
    esbuild,
    [
      path.join(WORK, "lib/audit", f),
      "--bundle",
      "--platform=node",
      "--format=esm",
      "--external:node:*",
      "--external:@solidity-parser/parser",
      "--external:antlr4ts",
      "--external:js-sha3",
      "--external:@electric-sql/pglite",
      "--external:@tanstack/react-start",
      "--external:vite",
      "--external:@/*",
      `--outfile=${path.join(WORK, "probe.mjs")}`,
      "--log-level=error",
    ],
    { cwd: WORK, encoding: "utf8" },
  );
  if (probe.status === 0) bundleable.add(f);
  else unbundleable.set(f, (probe.stderr || "").split("\n").find((l) => l.includes("ERROR")) ?? "unknown");
}
if (!asJson) {
  console.log(
    `binding check: ${bundleable.size}/${CORPUS.length} behavioural suites bundle here; the rest need dependencies this sandbox lacks`,
  );
}

const only = flag("only");
const detectors = only ? only.split(",").map((s) => s.trim()).filter(Boolean) : emittedDetectors();

rmSync(WORK, { recursive: true, force: true });
mkdirSync(WORK, { recursive: true });
// The repo's package.json sets "sideEffects": false, which lets esbuild drop a
// bare `import "./x.test.ts"` entirely — the bundle then contains no tests, the
// run passes, and every rule looks unbound. A work-dir package.json with
// sideEffects true is what makes the imports survive.
writeFileSync(
  path.join(WORK, "package.json"),
  JSON.stringify({ name: "detector-binding-check", sideEffects: true, type: "module" }, null, 2),
);

const results = [];
for (const detector of detectors) {
  const copy = path.join(WORK, "lib", "audit");
  rmSync(path.join(WORK, "lib"), { recursive: true, force: true });
  cpSync(path.join(ROOT, "src/lib"), path.join(WORK, "lib"), { recursive: true });

  // 1. Mutate: rename the emitted id, in whichever module emits it.
  const needle = `detector: "${detector}"`;
  const target = ["detect.ts", "bytecode.ts", "engine.ts"]
    .map((rel) => path.join(copy, rel))
    .find((abs) => {
      try {
        return readFileSync(abs, "utf8").includes(needle);
      } catch {
        return false;
      }
    });
  if (!target) {
    results.push({ detector, status: "no-emission", note: "no literal emission site found" });
    continue;
  }
  writeFileSync(target, readFileSync(target, "utf8").replaceAll(needle, `detector: "${detector}::MUTANT"`));

  // 2. Bundle a corpus entry that pulls in every behavioural suite.
  const entry = path.join(WORK, "entry.ts");
  writeFileSync(
    entry,
    CORPUS.filter((f) => bundleable.has(f))
      .map((f) => `import "./lib/audit/${f}";`)
      .join("\n"),
  );
  const bundle = path.join(WORK, "bundle.mjs");
  const built = spawnSync(
    esbuild,
    [
      entry,
      "--bundle",
      "--platform=node",
      "--format=esm",
      "--external:node:*",
      "--external:@solidity-parser/parser",
      "--external:antlr4ts",
      "--external:js-sha3",
      "--external:@electric-sql/pglite",
      "--external:@tanstack/react-start",
      "--external:vite",
      "--external:@/*",
      `--outfile=${bundle}`,
      "--log-level=error",
    ],
    { cwd: WORK, encoding: "utf8" },
  );
  if (built.status !== 0) {
    results.push({
      detector,
      status: "bundle-failed",
      note: (built.stderr || "").split("\n").find((l) => l.includes("ERROR")) ?? "bundle error",
    });
    continue;
  }

  // 3. Run. A mutation the corpus notices fails; one it ignores passes.
  const run = spawnSync(process.execPath, ["--test", bundle], { cwd: ROOT, encoding: "utf8" });
  const passed = run.status === 0;
  results.push({ detector, status: passed ? "UNBOUND" : "bound" });
}

rmSync(WORK, { recursive: true, force: true });

const unbound = results.filter((r) => r.status === "UNBOUND");
if (asJson) {
  console.log(JSON.stringify({ checked: results.length, unbound: unbound.map((r) => r.detector), results }, null, 2));
} else {
  for (const r of results) {
    if (r.status === "bound") continue;
    console.log(`${r.status.padEnd(14)} ${r.detector}${r.note ? `  (${r.note})` : ""}`);
  }
  const noEmission = results.filter((r) => r.status === "no-emission");
  const failed = results.filter((r) => r.status === "bundle-failed");
  const bound = results.filter((r) => r.status === "bound");
  console.log(
    `\n${results.length} detectors checked: ${bound.length} bound to a fixture, ${unbound.length} unbound, ${noEmission.length} with no literal emission site, ${failed.length} could not be mutated.`,
  );
  if (unbound.length > 0) {
    console.log("An unbound rule can stop emitting and no test notices. Write its fixture, or delete the rule.");
  }
}
process.exit(unbound.length > 0 ? 1 : 0);
