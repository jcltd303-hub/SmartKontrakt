// Unit tests for the Termux backend's forge test-count parser
// (parseForgeTestsRun in termux-backend/server.mjs). The parser is the
// backend half of the hollow-pass fix: forge exits 0 with "No tests
// found in project!" when nothing matched, so the executed-test count
// — not the exit code — decides whether a run may claim a verdict.
//
// Importing server.mjs starts its HTTP server; use a throwaway port
// and close the server when the file is done.
process.env.PORT = "18799";
const { parseForgeTestsRun, server } = await import("../termux-backend/server.mjs");
import { test, after } from "node:test";
import assert from "node:assert/strict";

after(() => server.close());

test("zero-match wording parses to 0 executed tests", () => {
  const out = [
    "Compiling 1 files with Solc 0.8.24",
    "Compiler run successful!",
    "Warning: No tests found in project! Forge looks for functions that start with `test`",
  ].join("\n");
  assert.equal(parseForgeTestsRun(out), 0);
});

test("final aggregate line gives the total (passed + failed + skipped)", () => {
  const out = [
    "Ran 2 tests for test/PoC.t.sol:PoC",
    "Suite result: FAILED. 1 passed; 1 failed; 0 skipped; finished in 772.77µs (460.24µs CPU time)",
    "Ran 1 test suite in 532.62ms (772.77µs CPU time): 1 tests passed, 1 failed, 0 skipped (2 total tests)",
  ].join("\n");
  assert.equal(parseForgeTestsRun(out), 2);
});

test("a single passing suite parses from the aggregate", () => {
  const out = "Ran 1 test suite in 12.00ms (5.00ms CPU time): 3 tests passed, 0 failed, 0 skipped (3 total tests)";
  assert.equal(parseForgeTestsRun(out), 3);
});

test("per-suite lines are summed when no aggregate is present", () => {
  const out = [
    "Suite result: ok. 3 passed; 0 failed; 0 skipped; finished in 1ms",
    "Suite result: FAILED. 0 passed; 2 failed; 1 skipped; finished in 1ms",
  ].join("\n");
  assert.equal(parseForgeTestsRun(out), 6);
});

test("a suite that ran zero tests parses to 0, not null", () => {
  assert.equal(parseForgeTestsRun("Suite result: ok. 0 passed; 0 failed; 0 skipped; finished in 1ms"), 0);
});

test("compile failure output carries no count evidence (null, keeps error classification)", () => {
  const out = "Compiler run failed:\nError (6275): Source file requires different compiler version";
  assert.equal(parseForgeTestsRun(out), null);
});

test("RPC failure output carries no count evidence (null)", () => {
  assert.equal(parseForgeTestsRun("Error: failed to fetch chain id: HTTP error 503"), null);
});

test("empty output is null", () => {
  assert.equal(parseForgeTestsRun(""), null);
  assert.equal(parseForgeTestsRun(null), null);
});
