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
