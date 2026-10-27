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
  // 7.5 after the 2026-10-27 rule work, up from 6.5. The raise is a DELIBERATE
  // trade and is recorded here so it cannot be re-baselined silently: the
  // pre-0.5 call fix (`.call.value(x)()` was invisible to the walker) took
  // unchecked_low_level_calls recall from 0.500 to 1.000, the pre-0.8
  // arithmetic rule took arithmetic from 0.000 to 0.867, and both add findings
  // — including findings on contracts the dataset does not label. Recall on the
  // two largest categories bought 0.9 more findings per contract.
  assert.ok(result.findingsPerFile <= 7.5, `noise rose to ${result.findingsPerFile} findings per contract`);

  // The headline number, and the floor for it. Per-category recall is the
  // diagnostic; this is what "how much of SmartBugs do we catch" means. 117 of
  // 143 (81.8%) as of 2026-10-27; the 26 misses are listed in the report, and
  // the biggest structural one is reentrancy inside a MODIFIER (modifier bodies
  // are not walked) — the rest are 5 denial_of_service (parked), 3
  // front_running, 3 time_manipulation, 2 arithmetic, and one each of
  // access_control / bad_randomness / other / short_addresses (retired).
  assert.ok(
    result.contractsCaught >= 117,
    `contracts caught fell to ${result.contractsCaught} of ${result.parsed}`,
  );

  const byId = Object.fromEntries(result.categories.map((c) => [c.category, c]));
  // Categories with real coverage must not silently lose it.
  assert.ok((byId["unchecked_low_level_calls"]?.recall ?? 0) >= 0.45, "low-level-call recall fell below 0.45");
  assert.ok((byId["bad_randomness"]?.recall ?? 0) >= 0.8, "randomness recall fell below 0.8");
  assert.ok((byId["access_control"]?.recall ?? 0) >= 0.9, "access-control recall fell below 0.9");
});
