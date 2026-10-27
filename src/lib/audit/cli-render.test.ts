import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import {
  bar, humanCount, humanDuration, renderFrame, renderLlm, renderMenu, renderProgress,
  renderQueue, renderStats, spinnerFrame, truncate, visibleLength,
} from "../../../cli/render.mjs";

const run = promisify(execFile);

/**
 * The terminal UI (2026-10-27).
 *
 * Rendering is pure so the interface is testable without a TTY; the last test
 * drives the real binary against a fake worker to prove the polling path.
 */

test("the progress bar clamps and fills proportionally", () => {
  assert.equal(bar(0, 10), "░".repeat(10));
  assert.equal(bar(1, 10), "█".repeat(10));
  assert.equal(bar(0.5, 10), "█".repeat(5) + "░".repeat(5));
  assert.equal(bar(-1, 10), "░".repeat(10), "below zero clamps");
  assert.equal(bar(2, 10), "█".repeat(10), "above one clamps");
  assert.equal(bar(NaN, 10), "░".repeat(10), "NaN does not explode");
});

test("durations and counts stay readable at every scale", () => {
  assert.equal(humanDuration(45_000), "45s");
  assert.equal(humanDuration(90_000), "1m30s");
  assert.equal(humanDuration(3_600_000), "1h00m");
  assert.equal(humanDuration(50 * 3_600_000), "2d02h");
  assert.equal(humanDuration(NaN), "—");
  assert.equal(humanCount(999), "999");
  assert.equal(humanCount(12_345), "12.3k");
  assert.equal(humanCount(2_500_000), "2.5M");
});

test("progress reports rate and ETA from the run's own clock", () => {
  const startedAt = new Date(Date.now() - 60_000).toISOString(); // one minute in
  const frame = renderProgress({
    status: { state: "running", total: 1000, completed: 100, failed: 0, startedAt, chainId: "ethereum" },
  });
  assert.match(frame, /10\.0%/, "100 of 1000");
  assert.match(frame, /addr\/s/, "rate is shown");
  assert.match(frame, /ETA/, "ETA is shown");
  assert.match(frame, /elapsed 1m/, "elapsed is shown");
});

test("a failed flush and a parked run are both visible", () => {
  const frame = renderProgress({
    status: { state: "paused", total: 100, completed: 40, failed: 7, pending: 3, lastError: "RPC_UNAVAILABLE at 0xabc" },
  });
  assert.match(frame, /7 failed/);
  assert.match(frame, /3 pending flush/);
  assert.match(frame, /RPC_UNAVAILABLE/);
});

test("LLM health maps each verdict to its own word", () => {
  for (const state of ["smooth", "degraded", "dead", "off", "waiting"]) {
    const frame = renderLlm({ llm: { verdict: { state, reason: "because" }, ok: 3, empty: 1, error: 0 } });
    assert.match(frame, new RegExp(state));
  }
  assert.match(renderLlm({ llm: null }), /unknown/, "a missing health endpoint reads as unknown");
});

test("the queue shows bands and says so when empty", () => {
  const queue = {
    counts: { readNow: 1, readNext: 1, needsLiveState: 0, background: 2, total: 4 },
    rows: [
      { band: "read-now", address: "0x1111111111", title: "sweep sends ether with no access check" },
      { band: "read-next", address: "0x2222222222", title: "loosened: hook settles at spot" },
    ],
  };
  const frame = renderQueue(queue);
  assert.match(frame, /now /);
  assert.match(frame, /next/);
  assert.match(frame, /1 now · 1 next/);
  assert.match(frame, /sweep sends ether/);
  assert.match(renderQueue(null), /nothing yet/);
});

test("stats render counts, and a database error is shown not swallowed", () => {
  // humanCount rounds to one decimal: 51960 -> 52.0k.
  assert.match(renderStats({ db: { scans: 15857, findings: 51960, critical: 1, high: 35 } }), /52\.0k findings/);
  assert.match(renderStats({ db: { error: "db: connect ECONNREFUSED" } }), /ECONNREFUSED/);
});

test("the menu marks exactly one row and lists every action", () => {
  const frame = renderMenu(2);
  assert.equal(frame.split("\n").length, 7);
  assert.match(frame, /▸s  Stats/);
  assert.equal(frame.split("▸").length, 2, "one selection");
});

test("truncate respects visible width and marks the cut", () => {
  assert.equal(truncate("short", 10), "short");
  const cut = truncate("a".repeat(50), 10);
  assert.equal(visibleLength(cut), 10);
  assert.ok(cut.endsWith("…"));
});

test("a full frame carries every panel", () => {
  const frame = renderFrame(
    {
      status: { state: "running", total: 10, completed: 4, chainId: "ethereum", shard: "1/4" },
      llm: { verdict: { state: "off", reason: "aiSecondPass is false" } },
      db: { scans: 4, findings: 12, critical: 0, high: 2 },
      queue: { counts: { readNow: 1 }, rows: [{ band: "read-now", address: "0xabc", title: "x" }] },
    },
    0,
    3,
  );
  for (const needle of ["SmartKontrakt", "running", "shard 1/4", "LLM", "Archive", "Read queue", "Run control"]) {
    assert.ok(frame.includes(needle), `frame is missing ${needle}`);
  }
  assert.match(frame, /[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]/, "the spinner animates while running");
});

test("the spinner advances and wraps", () => {
  assert.notEqual(spinnerFrame(0), spinnerFrame(1));
  assert.equal(spinnerFrame(10), spinnerFrame(0), "wraps at ten frames");
});

test("--once drives the real binary against a fake worker", async () => {
  const status = {
    state: "running", total: 1000, completed: 250, failed: 2, chainId: "ethereum",
    shard: "2/4", startedAt: new Date(Date.now() - 30_000).toISOString(),
  };
  const health = { verdict: { state: "smooth", reason: "9/9 usable replies" }, ok: 9, empty: 0, error: 0 };
  const server = http.createServer((req, res) => {
    const body = req.url === "/status" ? status : req.url === "/health/llm" ? health : {};
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(body));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  try {
    const { stdout } = await run(process.execPath, ["cli/audit-tui.mjs", "--once"], {
      env: { ...process.env, WORKER_URL: `http://127.0.0.1:${port}`, NO_COLOR: "1", DATABASE_URL: "" },
      cwd: process.cwd(),
    });
    assert.match(stdout, /running/);
    // done counts completed + failed: 250 + 2 = 252 of 1000.
    assert.match(stdout, /25\.2%/, "252 of 1000");
    assert.match(stdout, /smooth/);
    assert.match(stdout, /shard 2\/4/);
  } finally {
    server.close();
  }
});
