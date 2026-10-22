#!/usr/bin/env node
/**
 * Run the PoC fixture suite — the ground-truth half of the fallback library.
 *
 * Each fixture is a modernized port of a specific SmartBugs Curated contract
 * (provenance in the contract header) plus the harness that must REPRODUCE the
 * known bug, and — for the same harness — must NOT reproduce it against the
 * fixed variant. The second half is the precision check: a harness that fires
 * on patched code is a false positive.
 *
 * Requires `forge` on PATH:
 *   node scripts/run-poc-fixtures.mjs      (npm run check:fixtures)
 *
 * Not part of `npm test` — the CI image carries no Foundry toolchain.
 */
import { existsSync, mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const DIR = fileURLToPath(new URL("../foundry/poc-fixtures/", import.meta.url));

try {
  execFileSync("forge", ["--version"], { stdio: "pipe" });
} catch {
  console.error("forge not found on PATH — install Foundry (https://book.getfoundry.sh) first.");
  process.exit(2);
}

const fixtures = existsSync(join(DIR, "test"))
  ? readdirSync(join(DIR, "test")).filter((f) => f.endsWith(".t.sol"))
  : [];
if (fixtures.length === 0) {
  console.error(`no fixtures found under ${DIR}test`);
  process.exit(1);
}

try {
  if (!existsSync(join(DIR, "lib", "forge-std"))) {
    // Clone, not `forge install`: this ran in a repository whose submodule state
    // is not guaranteed, and `forge install` needs a git repository to attach a
    // submodule to. `lib/` is gitignored, so a plain clone is enough.
    console.log("fetching forge-std into foundry/poc-fixtures…");
    mkdirSync(join(DIR, "lib"), { recursive: true });
    execFileSync(
      "git",
      ["clone", "--depth", "1", "-q", "https://github.com/foundry-rs/forge-std", join(DIR, "lib", "forge-std")],
      { cwd: DIR, stdio: "inherit" },
    );
  }
  console.log(`running ${fixtures.length} fixture file(s): ${fixtures.join(", ")}`);
  execFileSync("forge", ["test", "-vv"], { cwd: DIR, stdio: "inherit" });
  console.log("\nall fixtures reproduced as expected");
} catch (err) {
  console.error("\nfixture suite FAILED — a harness did not reproduce, or fired on fixed code");
  console.error(String(err?.message ?? err).slice(0, 2000));
  process.exit(1);
}
