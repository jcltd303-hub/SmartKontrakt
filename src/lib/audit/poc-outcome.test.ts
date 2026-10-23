// src/lib/audit/poc-outcome.test.ts
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  countExecutableTestFunctions,
  effectivePocStatus,
  ensureExecutablePocTests,
  findingPocProvenance,
  hasSkipSentinel,
  hasZeroTestEvidence,
  pocOriginOfExecutedCode,
  savedStatusFromRun,
  hasUnadaptedEvidence,
  unadaptedTemplateCheck,
  unadaptedTemplateOutput,
  TODO_ABORT_MARKERS,
  UNADAPTED_SENTINEL,
  NO_TESTS_GENERATION_INSTRUCTION,
} from "./poc-outcome.ts";
import {
  POC_FALLBACK_TEMPLATES,
  POC_FALLBACK_TODO_REQUIREMENTS,
} from "./poc-fallbacks.ts";

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

describe("unadaptedTemplateCheck — the TODO pre-check", () => {
  const ALL_TODO: Record<string, string[]> = {
    "03-reentrancy-erc777.t.sol": ["TOKEN"],
    "04-reentrancy-erc721.t.sol": ["PRICE"],
    "09-tx-origin-phishing.t.sol": ["OWNER"],
    "16-oracle-manipulation.t.sol": ["ROUTER", "TOKEN_IN", "TOKEN_OUT", "WHALE"],
    "17-slippage-sandwich.t.sol": ["ROUTER", "TOKEN_IN", "TOKEN_OUT", "VICTIM", "WHALE"],
    "18-signature-replay.t.sol": ["MESSAGE_HASH"],
    "19-signature-malleability.t.sol": ["MESSAGE_HASH"],
    "22-msg-value-loop.t.sol": ["PRICE"],
    "35-flash-loan-generic.t.sol": ["POOL", "ASSET"],
    "36-merkle-double-claim.t.sol": ["proof", "AMOUNT"],
    "37-approval-abuse.t.sol": ["TOKEN", "VICTIM", "SPENDER"],
    "38-governance-flash-vote.t.sol": ["WHALE"],
    "40-erc4626-inflation.t.sol": ["WHALE"],
  };

  it("flags every TODO-blocked template as shipped, naming exactly its declared constants", () => {
    for (const [file, names] of Object.entries(ALL_TODO)) {
      const hit = unadaptedTemplateCheck(POC_FALLBACK_TEMPLATES[file]);
      assert.ok(hit, `${file} should be flagged unadapted as shipped`);
      assert.equal(hit.file, file);
      assert.deepEqual([...hit.unfilled].sort(), [...names].sort(), `${file} unfilled set`);
    }
  });

  it("the generated TODO map and this test's expectation agree (13 templates)", () => {
    assert.deepEqual(
      Object.keys(POC_FALLBACK_TODO_REQUIREMENTS).sort(),
      Object.keys(ALL_TODO).sort(),
    );
    for (const [file, names] of Object.entries(ALL_TODO)) {
      assert.deepEqual([...POC_FALLBACK_TODO_REQUIREMENTS[file]].sort(), [...names].sort(), file);
    }
  });

  it("an adapted template (constants filled) is NOT flagged", () => {
    const t09 = POC_FALLBACK_TEMPLATES["09-tx-origin-phishing.t.sol"].replace(
      "OWNER = address(0)",
      "OWNER = address(0x1234567890AbcdEF1234567890aBcdef12345678)",
    );
    assert.notEqual(t09, POC_FALLBACK_TEMPLATES["09-tx-origin-phishing.t.sol"]);
    assert.equal(unadaptedTemplateCheck(t09), null);

    const t22 = POC_FALLBACK_TEMPLATES["22-msg-value-loop.t.sol"].replace(
      "PRICE = 0;",
      "PRICE = 0.05 ether;",
    );
    assert.notEqual(t22, POC_FALLBACK_TEMPLATES["22-msg-value-loop.t.sol"]);
    assert.equal(unadaptedTemplateCheck(t22), null);
  });

  it("a partially adapted template names only the constants still unfilled", () => {
    const t36 = POC_FALLBACK_TEMPLATES["36-merkle-double-claim.t.sol"].replace(
      "AMOUNT = 0;",
      "AMOUNT = 100 ether;",
    );
    assert.notEqual(t36, POC_FALLBACK_TEMPLATES["36-merkle-double-claim.t.sol"]);
    const hit = unadaptedTemplateCheck(t36);
    assert.ok(hit);
    assert.equal(hit.file, "36-merkle-double-claim.t.sol");
    assert.deepEqual(hit.unfilled, ["proof"]);
  });

  it("does not flag non-template sources or TODO-free templates", () => {
    assert.equal(unadaptedTemplateCheck("contract Attack { function exploit() public {} }"), null);
    assert.equal(unadaptedTemplateCheck(""), null);
    assert.equal(unadaptedTemplateCheck(POC_FALLBACK_TEMPLATES["06-open-drain.t.sol"]), null);
    assert.equal(unadaptedTemplateCheck(POC_FALLBACK_TEMPLATES["46-token-rescue.t.sol"]), null);
  });

  it("every TODO abort marker appears verbatim in a shipped template source", () => {
    const allSources = Object.values(POC_FALLBACK_TEMPLATES).join("\n");
    for (const marker of TODO_ABORT_MARKERS) {
      assert.ok(allSources.includes(marker), `marker not in any template: ${marker}`);
    }
  });

  it("the saved output text carries the sentinel and names file + constants", () => {
    const out = unadaptedTemplateOutput("09-tx-origin-phishing.t.sol", ["OWNER"]);
    assert.ok(out.includes(UNADAPTED_SENTINEL));
    assert.ok(out.includes("09-tx-origin-phishing.t.sol"));
    assert.ok(out.includes("OWNER"));
    assert.ok(hasUnadaptedEvidence(out));
  });
});

describe("unadapted reclassification — savedStatusFromRun / effectivePocStatus", () => {
  const abortLogs =
    "Finding input SHA3-256: x\n[SmartPoC | Foundry] target=0xa chain=ethereum tests=1\n[FAIL: revert: set OWNER to the trusted victim account] test_exploit()";

  it("a failed run that aborted on a TODO precondition saves as unadapted", () => {
    assert.equal(savedStatusFromRun({ status: "failed", logs: abortLogs }), "unadapted");
  });

  it("an error run carrying the pre-check output saves as unadapted", () => {
    assert.equal(
      savedStatusFromRun({ status: "error", logs: unadaptedTemplateOutput("22-msg-value-loop.t.sol", ["PRICE"]) }),
      "unadapted",
    );
  });

  it("a passed run is never reclassified, even with marker-like text", () => {
    assert.equal(savedStatusFromRun({ status: "passed", logs: abortLogs }), "passed");
  });

  it("a plain failed run without TODO evidence stays failed", () => {
    assert.equal(savedStatusFromRun({ status: "failed", logs: "0 passed; 1 failed" }), "failed");
  });

  it("stored failed/error rows with TODO-abort output read as unadapted", () => {
    assert.equal(effectivePocStatus("failed", abortLogs), "unadapted");
    assert.equal(effectivePocStatus("error", abortLogs), "unadapted");
    assert.equal(effectivePocStatus("failed", "0 passed; 1 failed"), "failed");
    assert.equal(effectivePocStatus("error", "All RPC providers failed"), "error");
  });
});

describe("findingPocProvenance (G8) — origin + verdict travel on the Finding", () => {
  it("a finding saved from a template run reads back origin=template with its verdict", () => {
    // The chain saves a library template VERBATIM as the finding's
    // poc_code (templates are complete Test contracts), so the stored
    // code itself identifies the run as a template run.
    const provenance = findingPocProvenance({
      pocStatus: "failed",
      pocOutput: "0 passed; 1 failed",
      pocCode: POC_FALLBACK_TEMPLATES["06-open-drain.t.sol"],
    });
    assert.deepEqual(provenance, { origin: "template", verdict: "failed" });
  });

  it("a finding saved from a generated run reads back origin=generated", () => {
    const generated = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test} from "forge-std/Test.sol";
contract PoC is Test {
    function test_drain() public { assertTrue(true); }
}`;
    const provenance = findingPocProvenance({
      pocStatus: "passed",
      pocOutput: "1 passed; 0 failed",
      pocCode: generated,
    });
    assert.deepEqual(provenance, { origin: "generated", verdict: "passed" });
  });

  it("old-vocabulary rows reclassify at read time (error + zero-test output → no_tests)", () => {
    const provenance = findingPocProvenance({
      pocStatus: "error",
      pocOutput: "Suite result: FAILED. 0 passed; 0 failed; ran 0 tests",
      pocCode: null,
    });
    assert.deepEqual(provenance, { origin: "template", verdict: "no_tests" });
  });

  it("a TODO-abort output reclassifies a stored failed verdict to unadapted", () => {
    const provenance = findingPocProvenance({
      pocStatus: "failed",
      pocOutput: 'Error: set TOKEN to the ERC777 token address',
      pocCode: POC_FALLBACK_TEMPLATES["03-reentrancy-erc777.t.sol"],
    });
    assert.deepEqual(provenance, { origin: "template", verdict: "unadapted" });
  });

  it("a never-run finding has no provenance", () => {
    assert.equal(findingPocProvenance({ pocStatus: null, pocOutput: null, pocCode: null }), null);
    assert.equal(findingPocProvenance({}), null);
  });

  it("pocOriginOfExecutedCode: template source verbatim → template; anything else → generated", () => {
    assert.equal(pocOriginOfExecutedCode(POC_FALLBACK_TEMPLATES["46-token-rescue.t.sol"]), "template");
    assert.equal(pocOriginOfExecutedCode("contract Mine is Test { }"), "generated");
    assert.equal(pocOriginOfExecutedCode(null), "template"); // code-less rows take the house fallback
    assert.equal(pocOriginOfExecutedCode(""), "template");
  });
});
