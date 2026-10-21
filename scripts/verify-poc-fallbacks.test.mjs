import { test } from "node:test";
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

// Resolve relative to THIS file. The previous absolute `/app/applet/...` path
// was a build-sandbox leftover and could never work anywhere else.
// scripts/ -> repo root -> foundry/poc-fallbacks (one level up, not two).
const FALLBACKS_DIR = fileURLToPath(new URL("../foundry/poc-fallbacks/", import.meta.url));

async function harnessFiles() {
  return (await readdir(FALLBACKS_DIR)).filter((f) => f.endsWith(".t.sol")).sort();
}

test("every fallback harness is a runnable, fork-only Foundry test", async () => {
  const files = await harnessFiles();
  assert.ok(files.length >= 9, "at least one harness per SmartBugs category");
  for (const file of files) {
    const src = await readFile(join(FALLBACKS_DIR, file), "utf8");
    assert.match(src, /SPDX-License-Identifier/, `${file}: missing SPDX header`);
    assert.match(src, /pragma solidity \^?0\.8/, `${file}: must target Solidity >= 0.8`);
    assert.match(src, /import \{Test, console\} from "forge-std\/Test\.sol";/, `${file}: missing forge-std import`);
    assert.match(src, /contract PoC is Test/, `${file}: missing \`contract PoC is Test\``);
    assert.match(src, /function test_/, `${file}: no test function`);
    assert.match(src, /vm\.createFork\(/, `${file}: not fork-based`);
    assert.match(src, /vm\.envOr\("POC_TARGET"/, `${file}: must read POC_TARGET from env (no hardcoded target)`);
    assert.doesNotMatch(src, /--broadcast|privateKey|PRIVATE_KEY|vm\.broadcast/, `${file}: must never broadcast or take a key`);
  }
});

test("index.json, the harness files, and the SmartBugs taxonomy agree", async () => {
  const index = JSON.parse(await readFile(join(FALLBACKS_DIR, "index.json"), "utf8"));
  const onDisk = new Set(await harnessFiles());
  const listed = new Set(index.fallbacks.map((f) => f.file));

  for (const f of listed) assert.ok(onDisk.has(f), `index.json lists a missing harness: ${f}`);
  for (const f of onDisk) assert.ok(listed.has(f), `harness missing from index.json: ${f}`);

  const { SMARTBUGS_CATEGORIES, SMARTBUGS_BY_DETECTOR } = await import("../src/lib/audit/smartbugs.ts");

  // Every SmartBugs Curated (DASP) category must have at least one harness.
  const covered = new Set(index.fallbacks.map((f) => f.smartbugs));
  for (const category of SMARTBUGS_CATEGORIES) {
    assert.ok(covered.has(category.id), `no fallback harness for SmartBugs category: ${category.id}`);
  }

  // Every detector a harness claims must resolve to a SmartBugs category.
  for (const f of index.fallbacks) {
    for (const detector of f.detectors) {
      assert.ok(
        SMARTBUGS_BY_DETECTOR[detector],
        `detector "${detector}" (${f.file}) has no SmartBugs category`,
      );
    }
  }

  // The generated module must expose the same categories the taxonomy defines.
  const generated = await import("../src/lib/audit/poc-fallbacks.ts");
  const generatedCategories = Object.keys(generated.POC_FALLBACK_BY_SMARTBUGS).sort();
  const expected = SMARTBUGS_CATEGORIES.map((c) => c.id).sort();
  assert.deepEqual(generatedCategories, expected, "POC_FALLBACK_BY_SMARTBUGS must cover every category");

  // And every catalog entry must carry its category.
  for (const entry of generated.POC_FALLBACK_CATALOG) {
    assert.ok(entry.smartbugs, `catalog entry ${entry.file} is missing its SmartBugs category`);
  }
});

test("selectPocFallbacksBySmartbugs returns a harness for every category", async () => {
  const { selectPocFallbacksBySmartbugs, POC_FALLBACK_BY_SMARTBUGS } = await import(
    "../src/lib/audit/poc-fallbacks.ts"
  );
  for (const category of Object.keys(POC_FALLBACK_BY_SMARTBUGS)) {
    const picks = selectPocFallbacksBySmartbugs(category, 2);
    assert.ok(picks.length > 0, `no harness selected for category ${category}`);
    assert.match(picks[0].source, /contract PoC is Test/, `${category}: selected a non-harness`);
  }
});


/**
 * The ratchet: a template must not decide its verdict from ONE guessed entry
 * point, and must not assert a bare call success as the exploit.
 *
 * A single guess cannot tell "the vulnerability does not exist" from "the entry
 * point is called something else", and judging by whether a call returned is
 * wrong on its own — a no-op or already-guarded function returns successfully
 * and changes nothing (observed: `kill()` returned [Stop], moved 0 wei, and the
 * harness reported "not reproduced").
 *
 * `KNOWN` is the list still to convert. It may only SHRINK: adding a new
 * offender fails, and fixing one without removing it from the list also fails,
 * so the list cannot quietly go stale.
 */
test("no template decides from a single guessed call (ratchet)", async () => {
  const KNOWN = new Set([
    "04-reentrancy-erc721.t.sol",
    "05-reentrancy-read-only.t.sol",
    "24-div-before-mul.t.sol",
    "32-storage-collision-upgrade.t.sol",
    "33-shadowing-mismatch.t.sol",
    "40-erc4626-inflation.t.sol",
    "42-short-address-attack.t.sol",
    "43-front-running.t.sol",
    "44-external-contract-ref.t.sol",
    "45-timestamp-dependence.t.sol",
  ]);

  const dir = join(FIXTURES, "..", "poc-fallbacks");
  const files = (await readdir(dir)).filter((f) => f.endsWith(".t.sol"));
  const offenders = [];
  for (const file of files) {
    const src = await readFile(join(dir, file), "utf8");
    const why = [];
    if (/require\(\s*\w+\s*,\s*"[^"]*adapt/i.test(src)) why.push("adapt-guess");
    if (src.includes("TEMPLATE_NOT_ADAPTED")) why.push("stub");
    if (/assertTrue\(\s*ok\b/.test(src)) why.push("call-success");
    if (src.includes("vm.skip(")) why.push("skipped");
    if (/\bI\w+\(target\)\.\w+\(/.test(src) && !/_(attempt|tryEntry|tryDestroy)/.test(src)) {
      why.push("typed-single-guess");
    }
    if (why.length > 0) offenders.push(file);
  }

  const added = offenders.filter((f) => !KNOWN.has(f));
  assert.deepEqual(added, [], `new single-guess templates — convert them instead of adding to KNOWN: ${added.join(", ")}`);
  const fixed = [...KNOWN].filter((f) => !offenders.includes(f));
  assert.deepEqual(fixed, [], `these are converted now — remove them from KNOWN: ${fixed.join(", ")}`);
});
