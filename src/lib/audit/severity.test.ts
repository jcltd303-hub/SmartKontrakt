import test from "node:test";
import assert from "node:assert/strict";
import {
  SEVERITY_ORDER,
  SEVERITY_LABEL,
  bySeverity,
  isSeverity,
  severityRank,
} from "./severity.ts";

test("there is one severity ordering, most severe first", () => {
  assert.deepEqual([...SEVERITY_ORDER], ["critical", "high", "medium", "low", "info"]);
  assert.equal(severityRank("critical"), 0);
  assert.equal(severityRank("info"), SEVERITY_ORDER.length - 1);
  // An unknown value sorts last rather than throwing.
  assert.ok(severityRank("nope" as never) > severityRank("info"));
});

test("bySeverity sorts most severe first", () => {
  const xs = [{ severity: "low" }, { severity: "critical" }, { severity: "info" }, { severity: "high" }] as const;
  assert.deepEqual(
    [...xs].sort(bySeverity).map((x) => x.severity),
    ["critical", "high", "low", "info"],
  );
});

test("every severity has a label and isSeverity guards unknown input", () => {
  for (const s of SEVERITY_ORDER) {
    assert.ok(SEVERITY_LABEL[s].length > 0);
    assert.equal(isSeverity(s), true);
  }
  assert.equal(isSeverity("nope"), false);
  assert.equal(isSeverity(null), false);
  assert.equal(isSeverity(undefined), false);
});
