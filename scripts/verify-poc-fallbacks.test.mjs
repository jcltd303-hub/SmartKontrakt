import { test } from "node:test";
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { lintErrors } from "./single-guess-lint.mjs";

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
 * Every shape in which a harness can reach a verdict it has not earned — the
 * single-guess lint, which owns the rules now:
 *
 *   a single guessed call with no alternatives · a call-success assertion ·
 *   an adapt precondition · a stub · a skipped test · a vacuous catch · an
 *   always-pass assertion · an early return that empties the verdict · no
 *   assertion at all · an undisclosed failure message · a lone delegatecall
 *
 * The lint carries a synthetic positive AND negative for every rule
 * (single-guess-lint.test.mjs), because a rule that silently does not fire is
 * false confidence in exactly the direction that hides real findings — the
 * first version of this ratchet knew five shapes and missed a whole template.
 */
test("no template reaches a verdict it has not earned", async () => {
  const files = (await readdir(FALLBACKS_DIR)).filter((f) => f.endsWith(".t.sol")).sort();
  const offenders = [];
  for (const file of files) {
    const errs = lintErrors(await readFile(join(FALLBACKS_DIR, file), "utf8"));
    if (errs.length > 0) offenders.push(`${file}: ${errs.map((e) => e.shape).join(", ")}`);
  }
  assert.deepEqual(offenders, [], `templates with an unearned verdict:\n${offenders.join("\n")}`);
});
