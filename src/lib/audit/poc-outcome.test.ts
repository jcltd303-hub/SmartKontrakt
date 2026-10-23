// src/lib/audit/poc-outcome.test.ts
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  countExecutableTestFunctions,
  effectivePocStatus,
  ensureExecutablePocTests,
  hasSkipSentinel,
  hasZeroTestEvidence,
  savedStatusFromRun,
  NO_TESTS_GENERATION_INSTRUCTION,
} from "./poc-outcome.ts";

describe("countExecutableTestFunctions", () => {
  it("counts zero for a template/attack snippet with no test function", () => {
    const src = `pragma solidity ^0.8.24;
contract Attack {
    function exploit(address target) public { }
}`;
    assert.equal(countExecutableTestFunctions(src), 0);
  });

  it("counts a wrapped source's test functions (testPoc / test_ / testExploit)", () => {
    assert.equal(
      countExecutableTestFunctions(`contract PoC is Test { function testPoc() public { } }`),
      1,
    );
    assert.equal(
      countExecutableTestFunctions(
        `contract PoC is Test { function test_exploit() public { } function testRefund() external { } }`,
      ),
      2,
    );
    assert.equal(
      countExecutableTestFunctions(`contract PoC is Test { function testExploit() public { } }`),
      1,
    );
  });

  it("does not count commented-out test functions", () => {
    const src = `contract PoC is Test {
    // function test_exploit() public { }
    /* function testPoc() public { } */
    function helper() public { }
}`;
    assert.equal(countExecutableTestFunctions(src), 0);
  });

  it("does not count test functions inside string literals", () => {
    const src = `contract PoC is Test {
    string constant SAMPLE = "function test_exploit() public { }";
    function helper() public { }
}`;
    assert.equal(countExecutableTestFunctions(src), 0);
  });

  it("does not count internal/private or body-less declarations — forge never runs them", () => {
    assert.equal(
      countExecutableTestFunctions(`contract PoC is Test { function test_exploit() private { } }`),
      0,
    );
    assert.equal(
      countExecutableTestFunctions(`contract PoC is Test { function test_exploit() internal { } }`),
      0,
    );
    assert.equal(
      countExecutableTestFunctions(`interface IPoC { function test_exploit() external; }`),
      0,
    );
    // A view modifier between params and body keeps it executable.
    assert.equal(
      countExecutableTestFunctions(`contract PoC is Test { function test_check() public view returns (bool) { return true; } }`),
      1,
    );
  });

  it("ignores non-test functions and the bare name test", () => {
    assert.equal(
      countExecutableTestFunctions(`contract A { function test() public { } function attest() public { } }`),
      0,
    );
    assert.equal(countExecutableTestFunctions(""), 0);
  });
});

describe("savedStatusFromRun — fresh run results", () => {
  it("keeps real verdicts", () => {
    assert.equal(savedStatusFromRun({ status: "passed", logs: "1 passed; 0 failed" }), "passed");
    assert.equal(savedStatusFromRun({ status: "failed", logs: "0 passed; 1 failed" }), "failed");
  });

  it("maps tests=0 outcomes to no_tests, never error and never a verdict", () => {
    const header = "[SmartPoC | Foundry] target=0xabc chain=ethereum tests=0\nSHA-256: x";
    assert.equal(savedStatusFromRun({ status: "passed", logs: header }), "no_tests");
    assert.equal(savedStatusFromRun({ status: "failed", logs: header }), "no_tests");
    assert.equal(savedStatusFromRun({ status: "error", logs: header }), "no_tests");
    assert.equal(savedStatusFromRun({ status: "passed", logs: "No tests match the provided pattern. 0 passed; 0 failed" }), "no_tests");
    assert.equal(savedStatusFromRun({ status: "no_tests", logs: header }), "no_tests");
  });

  it("keeps the value-guard skip as skipped", () => {
    assert.equal(
      savedStatusFromRun({ status: "skipped", logs: "[SmartPoC] Skipped — target holds no value" }),
      "skipped",
    );
  });

  it("maps real failures to error (compile, backend unreachable, rpc)", () => {
    assert.equal(savedStatusFromRun({ status: "error", logs: "Compiler run failed: ParserError" }), "error");
    assert.equal(savedStatusFromRun({ status: "backend_unreachable", logs: "Backend not reachable" }), "error");
    assert.equal(savedStatusFromRun({ status: "error", logs: "All RPC providers failed" }), "error");
  });
});

describe("effectivePocStatus — stored rows reclassify on read", () => {
  const header0 = "Finding input SHA3-256: deadbeef\n[SmartPoC | Foundry] target=0xabc chain=ethereum tests=0\nSHA-256: x";

  it("reclassifies historical tests=0 'error' rows as no_tests", () => {
    assert.equal(effectivePocStatus("error", header0), "no_tests");
  });

  it("reclassifies historical value-guard skips saved as 'error' as skipped", () => {
    const out = "Finding input SHA3-256: deadbeef\n[SmartPoC] Skipped — target 0xabc holds no value (0 ETH, no priced token holdings) at the latest block";
    assert.equal(effectivePocStatus("error", out), "skipped");
    assert.ok(hasSkipSentinel(out));
  });

  it("leaves real errors, verdicts, and the new kinds untouched", () => {
    assert.equal(effectivePocStatus("error", "Compiler run failed: ParserError"), "error");
    assert.equal(effectivePocStatus("error", "Backend not reachable — start it in Termux"), "error");
    assert.equal(effectivePocStatus("passed", header0), "passed"); // only 'error' rows reclassify
    assert.equal(effectivePocStatus("failed", "0 passed; 1 failed"), "failed");
    assert.equal(effectivePocStatus("no_tests", header0), "no_tests");
    assert.equal(effectivePocStatus("skipped", null), "skipped");
    assert.equal(effectivePocStatus(null, header0), null);
    assert.equal(effectivePocStatus(undefined, undefined), null);
    assert.ok(hasZeroTestEvidence(header0));
    assert.ok(!hasZeroTestEvidence("[SmartPoC | Foundry] target=0xabc chain=ethereum tests=3"));
  });
});

describe("ensureExecutablePocTests — the generation gate", () => {
  const NO_TEST_SRC = `contract Attack { function exploit() public { } }`;
  const WITH_TEST_SRC = `contract PoC is Test { function test_exploit() public { } }`;

  it("passes a source with tests straight through — generation never invoked", async () => {
    let genCalls = 0;
    const res = await ensureExecutablePocTests(WITH_TEST_SRC, async () => {
      genCalls++;
      return null;
    });
    assert.equal(genCalls, 0);
    assert.equal(res.testCode, WITH_TEST_SRC);
    assert.equal(res.testCount, 1);
    assert.equal(res.generationAttempted, false);
  });

  it("0 tests → generation invoked once with the explicit instruction → yields tests → runnable", async () => {
    const instructions: string[] = [];
    const res = await ensureExecutablePocTests(NO_TEST_SRC, async (instruction) => {
      instructions.push(instruction);
      return WITH_TEST_SRC;
    });
    assert.equal(instructions.length, 1);
    assert.equal(instructions[0], NO_TESTS_GENERATION_INSTRUCTION);
    assert.match(instructions[0], /at least one public test function/);
    assert.equal(res.testCode, WITH_TEST_SRC);
    assert.equal(res.testCount, 1);
    assert.equal(res.generationAttempted, true);
  });

  it("0 tests → generation still yields none → no_tests outcome shape, generated source kept", async () => {
    const stillNone = `contract PoC is Test { function test_exploit() private { } }`;
    const res = await ensureExecutablePocTests(NO_TEST_SRC, async () => stillNone);
    assert.equal(res.testCount, 0);
    assert.equal(res.testCode, stillNone);
    assert.equal(res.generationAttempted, true);
    assert.match(res.generationNote ?? "", /still produced no executable test function/);
  });

  it("0 tests → generation throws or returns nothing → still a clean no_tests shape", async () => {
    const thrown = await ensureExecutablePocTests(NO_TEST_SRC, async () => {
      throw new Error("openrouter down");
    });
    assert.equal(thrown.testCount, 0);
    assert.equal(thrown.testCode, NO_TEST_SRC);
    const empty = await ensureExecutablePocTests(NO_TEST_SRC, async () => null);
    assert.equal(empty.testCount, 0);
    assert.match(empty.generationNote ?? "", /returned no source/);
  });
});

describe("UI counter math over a fabricated mixed archive", () => {
  // The exact partition the PoC Audits header computes with
  // effectivePocStatus: every stored row lands in exactly one bucket,
  // and the buckets plus unrun sum to the total.
  const rows: Array<{ pocStatus: string | null; pocOutput: string | null }> = [
    { pocStatus: "passed", pocOutput: "[SmartPoC | Foundry] target=0xa chain=ethereum tests=2" },
    { pocStatus: "failed", pocOutput: "0 passed; 1 failed" },
    { pocStatus: "failed", pocOutput: "0 passed; 1 failed" },
    { pocStatus: "error", pocOutput: "Compiler run failed: ParserError" },
    { pocStatus: "error", pocOutput: "Finding input SHA3-256: x\n[SmartPoC | Foundry] target=0xa chain=ethereum tests=0" },
    { pocStatus: "error", pocOutput: "Finding input SHA3-256: x\n[SmartPoC] Skipped — target 0xa holds no value" },
    { pocStatus: "error", pocOutput: "All RPC providers failed (tried 5)" },
    { pocStatus: "no_tests", pocOutput: "[SmartPoC] Not run — no executable test function" },
    { pocStatus: "skipped", pocOutput: "[SmartPoC] Skipped — target 0xa holds no value" },
    { pocStatus: null, pocOutput: null },
    { pocStatus: null, pocOutput: null },
  ];

  it("buckets sum to the total and errors are real errors only", () => {
    const count = (s: string) => rows.filter((r) => effectivePocStatus(r.pocStatus, r.pocOutput) === s).length;
    const buckets = {
      passed: count("passed"),
      failed: count("failed"),
      error: count("error"),
      no_tests: count("no_tests"),
      skipped: count("skipped"),
      unrun: rows.filter((r) => !r.pocStatus).length,
    };
    assert.deepEqual(buckets, { passed: 1, failed: 2, error: 2, no_tests: 2, skipped: 2, unrun: 2 });
    const sum = Object.values(buckets).reduce((a, b) => a + b, 0);
    assert.equal(sum, rows.length);
  });
});
