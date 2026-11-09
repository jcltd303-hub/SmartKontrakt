import test from "node:test";
import assert from "node:assert/strict";
import { resolvePocRepairRounds, DEFAULT_POC_REPAIR_ROUNDS } from "./foundry-backend.ts";

test("default is the ReX-style loop, not the old single shot", () => {
  assert.equal(resolvePocRepairRounds({}), DEFAULT_POC_REPAIR_ROUNDS);
  assert.ok(DEFAULT_POC_REPAIR_ROUNDS > 1, "one round is the behaviour this replaces");
});

test("POC_REPAIR_ROUNDS=0 restores single-shot", () => {
  assert.equal(resolvePocRepairRounds({ POC_REPAIR_ROUNDS: "0" }), 0);
});

test("an explicit round count is honoured", () => {
  assert.equal(resolvePocRepairRounds({ POC_REPAIR_ROUNDS: "5" }), 5);
});

test("garbage falls back to the default rather than disabling repair", () => {
  for (const bad of ["", "abc", "-1", "NaN"]) {
    assert.equal(resolvePocRepairRounds({ POC_REPAIR_ROUNDS: bad }), DEFAULT_POC_REPAIR_ROUNDS, bad);
  }
});

test("the budget decrements to zero and stops", () => {
  let left = resolvePocRepairRounds({ POC_REPAIR_ROUNDS: "2" });
  const rounds: number[] = [];
  while (left > 0) { rounds.push(left); left -= 1; }
  assert.deepEqual(rounds, [2, 1], "two repairs, then stop — never a third");
  assert.equal(left, 0);
});
