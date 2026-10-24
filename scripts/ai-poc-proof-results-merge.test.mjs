import { test } from "node:test";
import assert from "node:assert/strict";
import {
  isPassingRow,
  mergeResults,
  previousFields,
  selectRerunTypes,
} from "./ai-poc-proof/results-merge.mjs";

const types = [{ id: "01-a" }, { id: "02-b" }, { id: "03-c" }];
const row = (id, status, category, detail = "") => ({ id, status, category, detail });

test("passing is exactly the runner's own passing statuses", () => {
  assert.equal(isPassingRow(row("x", "PASS", "passed")), true);
  assert.equal(isPassingRow(row("x", "DRY-PASS", "passed")), true);
  assert.equal(isPassingRow(row("x", "FAIL", "generation")), false);
  assert.equal(isPassingRow(row("x", "DRY-FAIL", "assertion")), false);
  assert.equal(isPassingRow(row("x", "", "")), false);
  assert.equal(isPassingRow(undefined), false);
  assert.equal(isPassingRow(null), false);
});

test("selectRerunTypes: failures and unrecorded types re-run; passes do not", () => {
  const previous = [row("01-a", "PASS", "passed"), row("02-b", "FAIL", "generation")];
  const rerun = selectRerunTypes(types, previous).map((t) => t.id);
  // 02-b failed, 03-c has no entry at all (never recorded = no pass).
  assert.deepEqual(rerun, ["02-b", "03-c"]);
});

test("selectRerunTypes: with no previous rows everything re-runs", () => {
  assert.deepEqual(
    selectRerunTypes(types, []).map((t) => t.id),
    ["01-a", "02-b", "03-c"],
  );
});

test("previousFields: carries the earlier attempt; empty when there was none", () => {
  assert.deepEqual(previousFields(row("02-b", "FAIL", "generation", "fell back")), {
    previousStatus: "FAIL",
    previousCategory: "generation",
    previousDetail: "fell back",
  });
  assert.deepEqual(previousFields(undefined), {});
  assert.deepEqual(previousFields(null), {});
});

test("mergeResults: fresh wins by id, preserved rows pass through untouched, manifest order rules", () => {
  const preservedPass = row("01-a", "PASS", "passed", "original entry");
  const staleFail = row("02-b", "FAIL", "generation", "fell back");
  const fresh = {
    ...row("02-b", "PASS", "passed", "generated on the re-run"),
    ...previousFields(staleFail),
  };
  const merged = mergeResults(types, [preservedPass, staleFail], [fresh]);
  assert.deepEqual(
    merged.map((r) => r.id),
    ["01-a", "02-b"],
  );
  // Untouched means the same object — no re-serialization of history.
  assert.equal(merged[0], preservedPass);
  assert.equal(merged[1], fresh);
  assert.equal(merged[1].previousStatus, "FAIL");
  assert.equal(merged[1].previousCategory, "generation");
  assert.equal(merged[1].previousDetail, "fell back");
});

test("mergeResults: a previous row whose type left the manifest is kept, not deleted", () => {
  const orphan = row("99-gone", "FAIL", "assertion", "type removed from the library");
  const merged = mergeResults(types, [orphan], []);
  assert.deepEqual(
    merged.map((r) => r.id),
    ["99-gone"],
  );
  assert.equal(merged[0], orphan);
});

test("mergeResults: a preserved non-passing row (outside the --type selection) stays as recorded", () => {
  const notSelected = row("03-c", "FAIL", "compile", "did not compile");
  const fresh = row("01-a", "PASS", "passed");
  const merged = mergeResults(types, [notSelected], [fresh]);
  assert.deepEqual(
    merged.map((r) => r.id),
    ["01-a", "03-c"],
  );
  assert.equal(merged[1], notSelected);
});

test("mergeResults: all-fresh input comes back in manifest order", () => {
  const fresh = [
    row("03-c", "PASS", "passed"),
    row("01-a", "PASS", "passed"),
    row("02-b", "FAIL", "compile"),
  ];
  const merged = mergeResults(types, [], fresh);
  assert.deepEqual(
    merged.map((r) => r.id),
    ["01-a", "02-b", "03-c"],
  );
});
