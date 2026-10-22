import assert from "node:assert/strict";
import test from "node:test";
import {
  DB_FREE_TIER_CAP_BYTES,
  DB_SIZE_CRITICAL_BYTES,
  DB_SIZE_WARN_BYTES,
  dbSizeLevel,
  dbSizePercentOfCap,
  formatDbBytes,
} from "./db-size.ts";

/** Size guardrail presentation (#3): formatting and the exact amber/red
 *  boundaries (above 400 MB = amber, above 475 MB = red, cap 500 MB). */

const MB = 1024 * 1024;

test("threshold constants match the free-tier guardrail spec", () => {
  assert.equal(DB_FREE_TIER_CAP_BYTES, 500 * MB);
  assert.equal(DB_SIZE_WARN_BYTES, 400 * MB);
  assert.equal(DB_SIZE_CRITICAL_BYTES, 475 * MB);
});

test("dbSizeLevel flips strictly above 400 MB and 475 MB", () => {
  assert.equal(dbSizeLevel(0), "ok");
  assert.equal(dbSizeLevel(400 * MB), "ok");
  assert.equal(dbSizeLevel(400 * MB + 1), "warn");
  assert.equal(dbSizeLevel(475 * MB), "warn");
  assert.equal(dbSizeLevel(475 * MB + 1), "critical");
  assert.equal(dbSizeLevel(580 * MB), "critical"); // the Oct 2026 incident size
});

test("dbSizePercentOfCap rounds against the 500 MB cap", () => {
  assert.equal(dbSizePercentOfCap(0), 0);
  assert.equal(dbSizePercentOfCap(250 * MB), 50);
  assert.equal(dbSizePercentOfCap(500 * MB), 100);
  assert.equal(dbSizePercentOfCap(580 * MB), 116);
});

test("formatDbBytes renders B/KB/MB/GB with sane precision", () => {
  assert.equal(formatDbBytes(0), "0 B");
  assert.equal(formatDbBytes(843), "843 B");
  assert.equal(formatDbBytes(1536), "1.5 KB");
  assert.equal(formatDbBytes(420 * MB), "420 MB");
  assert.equal(formatDbBytes(584 * MB), "584 MB");
  assert.equal(formatDbBytes(1536 * MB), "1.5 GB");
  assert.equal(formatDbBytes(-1), "—");
  assert.equal(formatDbBytes(NaN), "—");
});
