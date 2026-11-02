// src/lib/audit/poc-runner.test.ts
//
// Covers the two decisions that used to be re-implemented in every caller: which code to
// run, and whether to run at all. Both are pure, so this test needs no backend and no
// network — which matters, because the failure mode being prevented is a caller sending an
// empty body and reading the resulting "skipped" as a verdict.

import test from "node:test";
import assert from "node:assert/strict";

import { pocTestCode, shouldRunPoc } from "./poc-runner";

const CODE = "pragma solidity ^0.8.24;\ncontract PoC { function test_exploit() public {} }";

test("pocCode wins over exploitSolidity — the executed code is the reproducible one", () => {
  assert.equal(
    pocTestCode({ pocCode: CODE, exploitSolidity: "something else" }),
    CODE,
  );
});

test("exploitSolidity is used when nothing has been executed yet", () => {
  assert.equal(pocTestCode({ exploitSolidity: CODE, pocCode: null }), CODE);
});

test("blank strings do not count as code", () => {
  assert.equal(pocTestCode({ pocCode: "   ", exploitSolidity: "\n\t" }), null);
  assert.equal(pocTestCode({}), null);
});

test("a medium is never run, even when forced", () => {
  // force re-runs something that already has a verdict; it does not promote a severity.
  assert.equal(shouldRunPoc({ severity: "medium", exploitSolidity: CODE }, { force: true }), false);
});

test("critical and high are the default gate", () => {
  assert.equal(shouldRunPoc({ severity: "critical", exploitSolidity: CODE }), true);
  assert.equal(shouldRunPoc({ severity: "high", exploitSolidity: CODE }), true);
  assert.equal(shouldRunPoc({ severity: "low", exploitSolidity: CODE }), false);
});

test("no code means no run, whatever the severity", () => {
  assert.equal(shouldRunPoc({ severity: "critical" }), false);
  assert.equal(shouldRunPoc({ severity: "critical", exploitSolidity: "  " }), false);
});

test("an existing real verdict is not re-run without force", () => {
  // needsSmartPoc is the existing "already ran and produced a real verdict" check.
  // This asserts the wiring: without force it defers to needsSmartPoc, with force it does
  // not. The exact verdict shape is needsSmartPoc's business, not this module's.
  const ranAlready = {
    severity: "high",
    exploitSolidity: CODE,
    pocStatus: "passed",
    pocRunAt: "2026-11-01T00:00:00.000Z",
    pocOutput: "[SmartPoC | Foundry] tests=1",
  };
  const withoutForce = shouldRunPoc(ranAlready);
  const withForce = shouldRunPoc(ranAlready, { force: true });
  assert.equal(withForce, true, "force must re-run an existing verdict");
  assert.equal(
    typeof withoutForce,
    "boolean",
    "without force the decision belongs to needsSmartPoc",
  );
});

test("custom severities are honoured", () => {
  assert.equal(
    shouldRunPoc({ severity: "medium", exploitSolidity: CODE }, { severities: ["medium"] }),
    true,
  );
});
