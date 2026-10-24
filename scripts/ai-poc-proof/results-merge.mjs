// results-merge.mjs — the pure selection/merge logic behind the
// ai-poc-proof runner's --only-failed flag, extracted for unit tests
// (scripts/ai-poc-proof-results-merge.test.mjs). The merge rewrites
// results.json, so its rules get tests, not vibes.
//
// Semantics:
//  - A recorded type counts as PASSING only under the runner's own
//    passing statuses (PASS live, DRY-PASS dry). Everything else —
//    FAIL, DRY-FAIL, or no entry at all — is (re-)run.
//  - Merging never rewrites history: entries for types that were not
//    re-run are carried over untouched (the same row objects), and a
//    re-run type's fresh entry keeps the earlier attempt visible via
//    previous* fields (see previousFields).

/** The only statuses that count as "already proven" for --only-failed. */
export const PASSING_STATUSES = new Set(["PASS", "DRY-PASS"]);

export function isPassingRow(row) {
  return Boolean(row) && PASSING_STATUSES.has(row.status);
}

/** The subset of `types` a --only-failed run must (re-)run. */
export function selectRerunTypes(types, previousRows) {
  const byId = new Map((previousRows ?? []).map((r) => [r.id, r]));
  return types.filter((t) => !isPassingRow(byId.get(t.id)));
}

/**
 * The previous* fields a fresh entry carries so the earlier attempt
 * survives the merge. Returns an empty object when there was no
 * earlier entry for the type (nothing to preserve).
 */
export function previousFields(previousRow) {
  if (!previousRow) return {};
  return {
    previousStatus: previousRow.status ?? "",
    previousCategory: previousRow.category ?? "",
    previousDetail: previousRow.detail ?? "",
  };
}

/**
 * Merge fresh rows over previous rows: fresh wins by id; output
 * follows manifest order, then any previous rows whose type is no
 * longer in the manifest (kept untouched — dropping them would lose
 * the record), then any fresh rows outside the manifest (defensive;
 * cannot happen while the runner selects from the manifest).
 */
export function mergeResults(manifestTypes, previousRows, freshRows) {
  const freshById = new Map(freshRows.map((r) => [r.id, r]));
  const previousById = new Map(previousRows.map((r) => [r.id, r]));
  const merged = [];
  const emitted = new Set();
  for (const t of manifestTypes) {
    const row = freshById.get(t.id) ?? previousById.get(t.id);
    if (row && !emitted.has(t.id)) {
      merged.push(row);
      emitted.add(t.id);
    }
  }
  for (const row of previousRows) {
    if (!emitted.has(row.id) && !freshById.has(row.id)) {
      merged.push(row);
      emitted.add(row.id);
    }
  }
  for (const row of freshRows) {
    if (!emitted.has(row.id)) {
      merged.push(row);
      emitted.add(row.id);
    }
  }
  return merged;
}
