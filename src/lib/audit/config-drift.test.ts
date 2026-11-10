import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  WORKER_START_DEFAULTS,
  WORKER_URL_DEFAULT,
} from "../config.ts";

/**
 * Drift alarm for the one runtime that cannot import the central config:
 * pipeline-worker/hellbent-feed.py is Python-stdlib-only, so it re-states
 * the worker URL / chain / delay defaults. If someone changes config.mjs
 * (or the feeder) without the other, this test fails — update the feeder
 * to match config.mjs, not the other way around.
 */
const feederSource = readFileSync(
  new URL("../../../pipeline-worker/hellbent-feed.py", import.meta.url),
  "utf8",
);

test("hellbent feeder worker URL default matches config", () => {
  assert.ok(
    feederSource.includes(`"${WORKER_URL_DEFAULT}"`),
    `hellbent-feed.py must default --worker to ${WORKER_URL_DEFAULT} (WORKER_URL_DEFAULT in src/lib/config.mjs)`,
  );
});

test("hellbent feeder chain default matches config", () => {
  assert.ok(
    feederSource.includes(`default="${WORKER_START_DEFAULTS.chainId}"`),
    `hellbent-feed.py must default --chain to "${WORKER_START_DEFAULTS.chainId}" (WORKER_START_DEFAULTS.chainId in src/lib/config.mjs)`,
  );
});

test("hellbent feeder delay default matches config", () => {
  assert.ok(
    feederSource.includes(`default=${WORKER_START_DEFAULTS.delayMs}`),
    `hellbent-feed.py must default --delay-ms to ${WORKER_START_DEFAULTS.delayMs} (WORKER_START_DEFAULTS.delayMs in src/lib/config.mjs)`,
  );
});

test("hellbent feeder names config.mjs as its source of truth", () => {
  assert.ok(
    feederSource.includes("src/lib/config.mjs"),
    "hellbent-feed.py must carry the pointer comment to src/lib/config.mjs",
  );
});

const serverSource = readFileSync(
  new URL("../../../termux-backend/server.mjs", import.meta.url),
  "utf8",
);

test("termux backend standalone fallback list matches config", async () => {
  const { ALL_RPC_URLS } = await import("../config.ts");
  const fbStart = serverSource.indexOf("/*FALLBACK_LITERAL_START*/");
  const fbEnd = serverSource.indexOf("/*FALLBACK_LITERAL_END*/");
  assert.ok(fbStart > 0 && fbEnd > fbStart, "fallback literal markers present in server.mjs");
  const literal = serverSource
    .slice(fbStart, fbEnd)
    .replace("/*FALLBACK_LITERAL_START*/", "")
    .trim();
  const fallback: string[] = new Function(`return (${literal.replace(/;$/, "")});`)() as string[];
  assert.deepEqual(
    fallback,
    ALL_RPC_URLS,
    "termux-backend/server.mjs standalone fallback must equal ALL_RPC_URLS in src/lib/config.mjs",
  );
});
