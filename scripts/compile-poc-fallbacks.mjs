#!/usr/bin/env node
/**
 * Compile every fallback PoC harness with Foundry, so a broken template fails
 * loudly instead of silently shipping. Requires `forge` on PATH.
 *
 *   node scripts/compile-poc-fallbacks.mjs
 *
 * Not part of `npm test`: one forge build per harness needs a Foundry toolchain
 * the CI image does not carry, and each build is seconds-to-minutes. The unit
 * test (scripts/verify-poc-fallbacks.test.mjs) does the fast structural +
 * SmartBugs-taxonomy checks; this script is the "does it actually compile" gate
 * for a machine that has Foundry (e.g. the Termux backend host).
 *
 * Each harness is compiled alone, because every file declares `contract PoC is
 * Test` — compiling them together would collide on the contract name.
 */
import { mkdtempSync, rmSync, cpSync, writeFileSync, readdirSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const SRC = fileURLToPath(new URL("../foundry/poc-fallbacks/", import.meta.url));
const files = readdirSync(SRC).filter((f) => f.endsWith(".t.sol")).sort();

function run(cmd, args, cwd) {
  return execFileSync(cmd, args, { cwd, stdio: "pipe", encoding: "utf8" });
}

let project;
try {
  run("forge", ["--version"]);
} catch {
  console.error("forge not found on PATH — install Foundry (https://book.getfoundry.sh) first.");
  process.exit(2);
}

let failed = 0;
try {
  project = mkdtempSync(join(tmpdir(), "kiln-fallbacks-"));
  mkdirSync(join(project, "src"), { recursive: true });
  mkdirSync(join(project, "test"), { recursive: true });
  writeFileSync(
    join(project, "foundry.toml"),
    '[profile.default]\nsrc = "src"\ntest = "test"\nlibs = ["lib"]\n',
  );
  console.log("installing forge-std into the temp project…");
  run("forge", ["install", "foundry-rs/forge-std", "--no-commit"], project);

  for (const file of files) {
    cpSync(join(SRC, file), join(project, "test", "Exploit.t.sol"));
    try {
      run("forge", ["build"], project);
      console.log("ok    ", file);
    } catch (err) {
      failed += 1;
      console.error("FAIL  ", file);
      console.error(String(err.stdout || err.stderr || err.message).slice(0, 1500));
    }
  }
} finally {
  if (project) rmSync(project, { recursive: true, force: true });
}

console.log(`\n${files.length - failed}/${files.length} harnesses compiled`);
process.exit(failed ? 1 : 0);
