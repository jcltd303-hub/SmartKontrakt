import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

/**
 * Wiring checks for pipeline-worker/worker.ts (2026-10-27).
 *
 * That file is a script: the run loop has no exportable seam, so a unit test
 * cannot execute it here (it needs a database, an RPC endpoint and a queue). What
 * it CAN pin is the wiring that broke in production:
 *
 *   [worker] run loop error: items is not defined
 *
 * `items` is local to handleStart; the loop only has `ctx.items`. esbuild bundles
 * happily either way — only a typecheck or a run catches it — so the assertion is
 * on the source text. Crude, but it fails loudly on exactly that mistake, and it
 * costs nothing to run in CI.
 */

const SRC = readFileSync("pipeline-worker/worker.ts", "utf8");

/** The run loop's own text, so assertions cannot match handleStart by accident. */
function runLoopBody(): string {
  const start = SRC.indexOf("async function runLoop");
  assert.ok(start > 0, "runLoop exists");
  const end = SRC.indexOf("\n// ---", start + 10);
  return SRC.slice(start, end > 0 ? end : SRC.length);
}

test("the run loop builds its queue keys from ctx.items, not a foreign `items`", () => {
  const body = runLoopBody();
  assert.match(body, /new Set\(ctx\.items\.map\(/, "queuedKeys must read ctx.items");
  assert.doesNotMatch(
    body,
    /\bnew Set\(items\./,
    "`items` is local to handleStart and is undefined inside runLoop — this is the bug that broke a live run",
  );
});

test("the loop follows proxy implementations using those keys", () => {
  const body = runLoopBody();
  assert.match(body, /implementationItems\(proxyInfo, item\.chainId, queuedKeys\)/);
  assert.match(body, /ctx\.items\.push\(/, "followed implementations join the live queue");
  assert.match(body, /status\.total = ctx\.items\.length/, "and progress counts them");
});

test("a run's shard is parsed before the list is filtered", () => {
  const start = SRC.indexOf("async function handleStart");
  const end = SRC.indexOf("status = {", start);
  const body = SRC.slice(start, end);
  assert.match(body, /parseShard\(body\.shard\)/, "shard is parsed");
  assert.match(body, /applyShard\(allItems, shard\)/, "and applied to the parsed list");
});

test("/status advertises the behaviours that changed observable output", () => {
  const m = SRC.match(/const FEATURES = \[([\s\S]*?)\] as const;/);
  assert.ok(m, "FEATURES exists");
  for (const feature of ["fourbyte-negative-cache", "proxy-follow", "shard", "sourcify-v2"]) {
    assert.ok(m![1]!.includes(feature), `FEATURES is missing ${feature}`);
  }
  assert.match(SRC, /features: FEATURES/, "and it is returned by /status");
});

test("the run loop tries code dedupe, and fails open when it cannot", () => {
  // 2026-10-28: 1595 scans over 375 distinct bodies. The lookup must be attempted,
  // must pass the body through, and must never be able to fail an item.
  const src = readFileSync("pipeline-worker/worker.ts", "utf8");
  assert.match(src, /findSiblingScan\(dedupeSql/, "the sibling lookup is wired");
  assert.match(src, /codeHashOf\(code\)/, "the hash is computed from fetched bytecode");
  assert.match(src, /bodyOverride/, "the override reaches analyzeAddress");
  assert.match(
    src,
    /catch \{\s*\n\s*\/\/ no dedupe for this item; the normal path is unchanged/,
    "the lookup is fail-open: a failure degrades to the normal path",
  );
  assert.match(src, /reused an earlier scan of identical code/, "the run summary reports reuse");
});

test("a second /start cannot slip past the idle guard", () => {
  // 2026-10-28: two /start calls seconds apart both announced "started:", because
  // handleStart is invoked as `void handleStart(...)` and awaited readJsonBody and the
  // address-file read before `status.state` became "running". Two live run loops then
  // share runCtx, runSeen, the batch buffer and the auto-PoC state, and the second
  // run's item list replaces the first mid-flight.
  const src = readFileSync("pipeline-worker/worker.ts", "utf8");
  const start = src.indexOf("async function handleStart");
  assert.ok(start > 0, "handleStart exists");
  const body = src.slice(start, start + 3000);

  // The claim must come before the first await, so the check and the assignment are
  // atomic under Node's single thread.
  const claimAt = body.indexOf('status.state = "running";');
  // indexOf("await ") matches the word inside the comment above, so target the
  // statement itself.
  const firstAwait = body.indexOf("await readJsonBody(req)");
  assert.ok(claimAt > 0, "handleStart claims the run");
  assert.ok(firstAwait > 0, "handleStart awaits something");
  assert.ok(
    claimAt < firstAwait,
    "the state must be claimed BEFORE the first await, or two starts both pass the guard",
  );
  assert.match(body, /if \(status\.state !== "idle"\)/, "the idle guard is still there");
  // And every early return after the claim must release it, or the worker wedges.
  const afterClaim = body.slice(claimAt);
  const returns = (afterClaim.match(/\breturn;/g) ?? []).length;
  const releases = (afterClaim.match(/status\.state = "idle";/g) ?? []).length;
  assert.ok(releases >= returns, `every early return releases the claim (${returns} returns, ${releases} releases)`);
});

test("the Status literal initialises every required field", () => {
  // 2026-10-29: `llm` and `llmVerdict` were declared required on `Status` but missing
  // from the literal. At runtime the second pass read `status.llmVerdict.state` on
  // undefined, the catch handler then called `recordLlm(status.llm, ...)` which threw
  // `reading 'calls'`, and that throw escaped the catch and PARKED the run.
  //
  // Nothing caught it because tsconfig's include is ["src", "server"] — pipeline-worker
  // has never been type-checked. This test is a stand-in until it is.
  const src = readFileSync("pipeline-worker/worker.ts", "utf8");
  const start = src.indexOf("let status: Status = {");
  assert.ok(start > 0, "the Status literal exists");
  const end = src.indexOf("\n};", start);
  assert.ok(end > start, "the literal terminates");
  const literal = src.slice(start, end);

  // Every field named on the Status type must appear in the literal.
  const typeStart = src.indexOf("type Status = {");
  const typeEnd = src.indexOf("\n};", typeStart);
  const typeBody = src.slice(typeStart, typeEnd);
  const fields = [...typeBody.matchAll(/^\s{2}([A-Za-z_][\w]*)\??:/gm)].map((m) => m[1]!);
  assert.ok(fields.length > 10, `parsed ${fields.length} fields from Status`);
  const missing = fields.filter((f) => !new RegExp(`\\b${f}\\s*:`).test(literal));
  assert.deepEqual(missing, [], `missing from the Status literal: ${missing.join(", ")}`);
});
