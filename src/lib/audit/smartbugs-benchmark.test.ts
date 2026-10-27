import test from "node:test";
import assert from "node:assert/strict";

import { runBenchmark } from "../../../scripts/benchmark-smartbugs.ts";

/**
 * The benchmark as a gate (2026-10-27).
 *
 * `scripts/benchmark-smartbugs.ts` scores the detectors against SmartBugs
 * Curated — 143 contracts with hand-annotated categories. This test runs it and
 * fails on any regression against `scripts/smartbugs-baseline.json`: recall
 * down, precision down, or findings-per-contract up.
 *
 * Re-baseline deliberately, with `--write`, and say in the commit message which
 * trade the new numbers represent. A silent re-baseline is how a benchmark
 * stops being one.
 */
test("detection benchmark does not regress against the committed baseline", () => {
  const result = runBenchmark();
  assert.ok(result.parsed >= 140, `expected the vendored corpus to analyse, got ${result.parsed}`);
  assert.ok(result.totalFindings > 0, "the analyzer produced no findings at all on a vulnerable corpus");

  // The per-category table is asserted against the committed baseline by the
  // script itself; here we pin the two numbers that summarise it, so a change
  // in either direction is visible in the test output rather than only in a
  // regenerated report.
  assert.ok(result.findingsPerFile <= 6.5, `noise rose to ${result.findingsPerFile} findings per contract`);

  const byId = Object.fromEntries(result.categories.map((c) => [c.category, c]));
  // Categories with real coverage must not silently lose it.
  assert.ok((byId["unchecked_low_level_calls"]?.recall ?? 0) >= 0.45, "low-level-call recall fell below 0.45");
  assert.ok((byId["bad_randomness"]?.recall ?? 0) >= 0.8, "randomness recall fell below 0.8");
  assert.ok((byId["access_control"]?.recall ?? 0) >= 0.9, "access-control recall fell below 0.9");
});
