import test from "node:test";
import assert from "node:assert/strict";

import { runIncidentBenchmark } from "../../../scripts/benchmark-incidents.ts";

/**
 * The 2026-era corpus gate (2026-10-27).
 *
 * `benchmark-smartbugs.ts` scores the rules against SmartBugs Curated, which is
 * 2018-era: it cannot fire a Uniswap-v4 hook rule, an EIP-7702 guard rule or a
 * shared-unlock netting rule, because those shapes did not exist when the
 * dataset was built. Every class added after the 2026 work was therefore
 * asserted by fixtures and never measured.
 *
 * This gate measures them: 12 detectors, each with a positive fixture (must
 * fire) and a control (must not), scored for recall and for CROSS-TALK — a
 * finding on a fixture whose manifest entry does not expect or justify it.
 */
test("the 2026-era incident corpus scores with no recall loss and no unexplained cross-talk", () => {
  const r = runIncidentBenchmark();

  // 12 detectors x (positive + control) = 24, plus the real KolanHook case added
  // from the vendored PoC after the name-keyed rule was found to miss it.
  assert.equal(r.cases, 25, "the corpus holds 12 detector pairs plus the real KolanHook entry point");
  assert.equal(r.recall, 1, `recall fell to ${(r.recall * 100).toFixed(1)}% — a positive fixture no longer fires`);

  // Cross-talk is the measurement a fixture corpus is uniquely able to make:
  // every finding that is neither the detector under test nor a justified
  // co-fire. Zero here means the rules are separable on these shapes.
  const unexpected = r.rows.filter((row) => row.unexpected.length > 0);
  assert.deepEqual(
    unexpected.map((row) => `${row.id}: ${row.unexpected.join(", ")}`),
    [],
    "unexplained cross-talk: either a rule fires on a shape it should not, or the co-fire is correct and belongs in the manifest's tolerate list with a reason",
  );

  // Every detector must have at least one positive that fires. hook-callback-auth
  // has two: the v4 callback shape and the real KolanHook settlement entry.
  for (const [det, bucket] of Object.entries(r.byDetector)) {
    assert.ok(bucket.positives >= 1, `${det} needs a positive fixture`);
    assert.equal(bucket.hit, bucket.positives, `${det} has a positive fixture that does not fire`);
  }
});
