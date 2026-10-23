// src/lib/audit/adjudicate-chain.test.ts
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runAdjudicationChain, type AdjudicationDeps } from "./adjudicate-chain.ts";
import { pocRunKey } from "./poc-run-key.ts";
import type { Finding } from "./types.ts";

const TEST_SNIPPET = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "forge-std/Test.sol";
contract PoC is Test {
    function test_exploit() public { assertTrue(true); }
}`;

function makeFinding(partial: Partial<Finding> = {}): Finding {
  return {
    id: "scan-1:0",
    severity: "critical",
    swc: null,
    title: "Reentrant withdraw",
    confidence: "high",
    detector: "reentrancy",
    summary: "withdraw sends ETH before updating the ledger",
    walkthrough: "…",
    exploitSolidity: TEST_SNIPPET,
    remediationSolidity: "",
    locationFn: "withdraw",
    locationLine: 12,
    snippet: "call.value(amount)()",
    ...partial,
  };
}

function makeDeps(overrides: Partial<AdjudicationDeps> = {}) {
  const calls = { ai: 0, persistReview: 0, run: 0, repair: 0, save: 0, list: 0 };
  const saved: Array<Parameters<AdjudicationDeps["saveRun"]>[0]> = [];
  const deps: AdjudicationDeps = {
    requestAiReview: async () => {
      calls.ai++;
      return { threatModelReport: "review", foundryTestCode: "", economicRiskSummary: "", source: "openrouter" as const };
    },
    persistAiReview: async () => {
      calls.persistReview++;
    },
    listRuns: async () => {
      calls.list++;
      return [];
    },
    runPoc: async () => {
      calls.run++;
      return { status: "passed", logs: "1 passed; 0 failed", durationMs: 42 };
    },
    repairPoc: async () => {
      calls.repair++;
      return TEST_SNIPPET;
    },
    isCompileError: (logs) => logs.includes("Compiler run failed"),
    saveRun: async (record) => {
      calls.save++;
      saved.push(record);
    },
    ...overrides,
  };
  return { deps, calls, saved };
}

const baseCtx = (partial: Record<string, unknown> = {}) => ({
  scanId: "scan-1",
  finding: makeFinding(),
  body: "contract Vault { function withdraw() external {} }",
  findings: [makeFinding()],
  contractName: "Vault",
  targetAddress: "0x3dfd23a6c5e8bbcfc9581d2e864a68feb6a076d3",
  chainId: "ethereum",
  aiReview: null,
  disposition: null,
  ...partial,
});

describe("runAdjudicationChain", () => {
  it("fresh finding: generates the review once, runs once, saves once, suggests confirmed on a pass", async () => {
    const { deps, calls, saved } = makeDeps();
    const outcome = await runAdjudicationChain(baseCtx(), deps);
    assert.equal(outcome.kind, "suggested");
    assert.equal(outcome.verdict, "passed");
    assert.equal(outcome.suggestion, "confirmed");
    assert.equal(outcome.reviewStep, "generated");
    assert.equal(outcome.runStep, "executed");
    assert.deepEqual(
      { ai: calls.ai, persist: calls.persistReview, run: calls.run, save: calls.save },
      { ai: 1, persist: 1, run: 1, save: 1 },
    );
    assert.equal(saved[0].status, "passed");
    assert.equal(saved[0].findingId, "scan-1:0");
    assert.ok(saved[0].output.includes("Finding input SHA3-256:"));
  });

  it("reuses the review and the stored run for the same digest — no OpenRouter call, no backend run, no save", async () => {
    const digest = pocRunKey("scan-1:0", TEST_SNIPPET).digest;
    const { deps, calls } = makeDeps({
      listRuns: async () => [
        { id: "poc:scan-1:0:x", status: "failed", sourceDigest: digest, output: "stored logs", durationMs: 7, createdAt: "2026-10-23T00:00:00Z" },
      ],
    });
    const outcome = await runAdjudicationChain(
      baseCtx({ aiReview: { threatModelReport: "r", foundryTestCode: "", economicRiskSummary: "", source: "openrouter" as const } }),
      deps,
    );
    assert.equal(outcome.kind, "suggested");
    assert.equal(outcome.runStep, "reused");
    assert.equal(outcome.reviewStep, "reused");
    assert.equal(outcome.verdict, "failed");
    assert.equal(outcome.suggestion, "false_positive");
    assert.equal(outcome.output, "stored logs");
    assert.equal(calls.ai, 0);
    assert.equal(calls.run, 0);
    assert.equal(calls.save, 0);
  });

  it("short-circuits an already-disposed finding: no AI call, no run, no save", async () => {
    const { deps, calls } = makeDeps();
    const outcome = await runAdjudicationChain(
      baseCtx({
        disposition: { findingId: "scan-1:0", disposition: "false_positive" as const, note: null, updatedAt: "2026-10-23T00:00:00Z" },
      }),
      deps,
    );
    assert.equal(outcome.kind, "already_adjudicated");
    assert.equal(outcome.suggestion, "false_positive");
    assert.equal(calls.ai, 0);
    assert.equal(calls.run, 0);
    assert.equal(calls.save, 0);
  });

  it("redo (force) re-executes despite a disposition and a matching stored run", async () => {
    const digest = pocRunKey("scan-1:0", TEST_SNIPPET).digest;
    const { deps, calls } = makeDeps({
      listRuns: async () => [
        { id: "r", status: "failed", sourceDigest: digest, output: "old", durationMs: 1, createdAt: "2026-10-23T00:00:00Z" },
      ],
    });
    const outcome = await runAdjudicationChain(
      baseCtx({
        force: true,
        disposition: { findingId: "scan-1:0", disposition: "false_positive" as const, note: null, updatedAt: "2026-10-23T00:00:00Z" },
        aiReview: { threatModelReport: "r", foundryTestCode: "", economicRiskSummary: "", source: "openrouter" as const },
      }),
      deps,
    );
    assert.equal(outcome.kind, "suggested");
    assert.equal(outcome.runStep, "executed");
    assert.equal(calls.run, 1);
    assert.equal(calls.ai, 0); // review still reused under redo
    assert.equal(outcome.verdict, "passed");
  });

  it("a backend failure becomes an error verdict → needs_more_info, and the error run is still saved", async () => {
    const { deps, saved } = makeDeps({
      runPoc: async () => {
        throw new Error("backend unreachable");
      },
    });
    const outcome = await runAdjudicationChain(baseCtx(), deps);
    assert.equal(outcome.verdict, "error");
    assert.equal(outcome.suggestion, "needs_more_info");
    assert.equal(saved.length, 1);
    assert.equal(saved[0].status, "error");
    assert.ok(saved[0].output.includes("backend unreachable"));
  });

  it("a not-reproduced run suggests false_positive", async () => {
    const { deps } = makeDeps({
      runPoc: async () => ({ status: "failed", logs: "0 passed; 1 failed", durationMs: 9 }),
    });
    const outcome = await runAdjudicationChain(baseCtx(), deps);
    assert.equal(outcome.verdict, "failed");
    assert.equal(outcome.suggestion, "false_positive");
  });

  it("a hollow PASS (zero tests matched) is a no_tests verdict, never confirmed and not an error", async () => {
    const { deps, saved } = makeDeps({
      runPoc: async () => ({ status: "passed", logs: "No tests match the provided pattern. 0 passed; 0 failed", durationMs: 3 }),
    });
    const outcome = await runAdjudicationChain(baseCtx(), deps);
    assert.equal(outcome.verdict, "no_tests");
    assert.equal(outcome.suggestion, "needs_more_info");
    assert.equal(saved[0].status, "no_tests");
  });

  it("repairs a compile error once and saves the repaired source", async () => {
    const repairedCode = `${TEST_SNIPPET}\n// repaired`;
    let runs = 0;
    const { deps, saved } = makeDeps({
      runPoc: async () => {
        runs++;
        return runs === 1
          ? { status: "error", logs: "Compiler run failed: ParserError", durationMs: 5 }
          : { status: "passed", logs: "1 passed; 0 failed", durationMs: 5 };
      },
      repairPoc: async () => repairedCode,
    });
    const outcome = await runAdjudicationChain(baseCtx(), deps);
    assert.equal(outcome.verdict, "passed");
    assert.equal(runs, 2);
    assert.equal(saved[0].source, repairedCode);
  });

  it("an AI review failure never blocks the PoC verdict", async () => {
    const { deps } = makeDeps({
      requestAiReview: async () => {
        throw new Error("openrouter down");
      },
    });
    const outcome = await runAdjudicationChain(baseCtx(), deps);
    assert.equal(outcome.reviewStep, "failed");
    assert.equal(outcome.verdict, "passed");
    assert.equal(outcome.suggestion, "confirmed");
  });

  it("a scan without a target address ends in an error outcome without touching the backend", async () => {
    const { deps, calls } = makeDeps();
    const outcome = await runAdjudicationChain(baseCtx({ targetAddress: null }), deps);
    assert.equal(outcome.kind, "error");
    assert.equal(outcome.suggestion, "needs_more_info");
    assert.equal(calls.run, 0);
  });
});

// A complete Test contract whose only test function is PRIVATE: the
// wrapper passes it through unchanged (its check does not look at
// visibility), forge would run 0 tests — exactly the shape the
// generation gate exists for.
const PRIVATE_TEST_SNIPPET = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "forge-std/Test.sol";
contract PoC is Test {
    function test_exploit() private { assertTrue(true); }
}`;

describe("runAdjudicationChain outcome kinds — no_tests and skipped", () => {
  it("gate: a PoC with no executable test gets one generation attempt, then runs the generated source", async () => {
    const { deps, calls, saved } = makeDeps();
    const outcome = await runAdjudicationChain(
      baseCtx({ finding: makeFinding({ exploitSolidity: PRIVATE_TEST_SNIPPET }) }),
      deps,
    );
    // Default repairPoc returns TEST_SNIPPET (a real test function).
    assert.equal(calls.repair, 1); // the gate's single generation attempt
    assert.equal(calls.run, 1); // backend ran the generated source
    assert.equal(outcome.verdict, "passed");
    assert.equal(saved[0].source, TEST_SNIPPET);
    assert.equal(saved[0].status, "passed");
  });

  it("gate: generation still yields no test → no_tests saved, backend never called, outcome complete", async () => {
    const { deps, calls, saved } = makeDeps({
      repairPoc: async () => PRIVATE_TEST_SNIPPET, // still no executable test
    });
    const outcome = await runAdjudicationChain(
      baseCtx({ finding: makeFinding({ exploitSolidity: PRIVATE_TEST_SNIPPET }) }),
      deps,
    );
    assert.equal(calls.run, 0); // no wasted fork run
    assert.equal(calls.save, 1);
    assert.equal(saved[0].status, "no_tests");
    assert.equal(outcome.verdict, "no_tests");
    assert.equal(outcome.suggestion, "needs_more_info");
    assert.equal(outcome.runStep, "skipped");
    assert.equal(outcome.steps.harness, "skipped");
    assert.equal(outcome.steps.saved, "done");
    // A no_tests outcome is terminal, not an incompletion.
    assert.equal(outcome.complete, true);
    assert.equal(outcome.stoppedAt, null);
    assert.match(saved[0].output, /no executable test function/);
  });

  it("a value-guard skip is saved as skipped — terminal and complete, not an error", async () => {
    const { deps, saved } = makeDeps({
      runPoc: async () => ({
        status: "skipped",
        logs: "[SmartPoC] Skipped — target 0x3dfd holds no value (0 ETH, no priced token holdings) at the latest block",
        durationMs: 0,
      }),
    });
    const outcome = await runAdjudicationChain(baseCtx(), deps);
    assert.equal(outcome.verdict, "skipped");
    assert.equal(outcome.suggestion, "needs_more_info");
    assert.equal(saved[0].status, "skipped");
    assert.equal(outcome.steps.harness, "skipped");
    assert.equal(outcome.steps.saved, "done");
    assert.equal(outcome.complete, true);
    assert.equal(outcome.stoppedAt, null);
  });

  it("a stored tests=0 run from the old vocabulary reuses as no_tests, not error", async () => {
    const digest = pocRunKey("scan-1:0", TEST_SNIPPET).digest;
    const { deps, calls } = makeDeps({
      listRuns: async () => [
        {
          id: "poc:scan-1:0:y",
          status: "error",
          sourceDigest: digest,
          output: "[SmartPoC | Foundry] target=0x3dfd chain=ethereum tests=0\nSHA-256: x",
          durationMs: 3,
          createdAt: "2026-10-23T00:00:00Z",
        },
      ],
    });
    const outcome = await runAdjudicationChain(
      baseCtx({ aiReview: { threatModelReport: "r", foundryTestCode: "", economicRiskSummary: "", source: "openrouter" as const } }),
      deps,
    );
    assert.equal(outcome.runStep, "reused");
    assert.equal(outcome.verdict, "no_tests");
    assert.equal(outcome.suggestion, "needs_more_info");
    assert.equal(calls.run, 0);
  });
});

describe("runAdjudicationChain step completeness", () => {
  it("a full fresh run completes all four steps (fetch/llm/harness/saved)", async () => {
    const events: Array<[string, string]> = [];
    const { deps } = makeDeps({
      onStep: (s, st) => events.push([s, st]),
    });
    const outcome = await runAdjudicationChain(baseCtx(), deps);
    assert.deepEqual(outcome.steps, { fetch: "done", llm: "done", harness: "done", saved: "done" });
    assert.equal(outcome.complete, true);
    assert.equal(outcome.stoppedAt, null);
    assert.ok(events.some(([s, st]) => s === "llm" && st === "running"));
    assert.ok(events.some(([s, st]) => s === "harness" && st === "done"));
    assert.ok(events.some(([s, st]) => s === "saved" && st === "done"));
  });

  it("an AI failure makes the chain INCOMPLETE at llm even though a verdict exists", async () => {
    const { deps } = makeDeps({
      requestAiReview: async () => {
        throw new Error("openrouter down");
      },
    });
    const outcome = await runAdjudicationChain(baseCtx(), deps);
    assert.equal(outcome.verdict, "passed"); // the harness still produced one
    assert.equal(outcome.complete, false);
    assert.equal(outcome.stoppedAt, "llm");
    assert.equal(outcome.steps.llm, "failed");
    assert.equal(outcome.steps.harness, "done");
    assert.equal(outcome.steps.saved, "done");
  });

  it("a backend transport failure stops at harness; the error run is still saved", async () => {
    const { deps, calls } = makeDeps({
      runPoc: async () => {
        throw new Error("connect ECONNREFUSED");
      },
    });
    const outcome = await runAdjudicationChain(baseCtx(), deps);
    assert.equal(outcome.steps.harness, "failed");
    assert.equal(outcome.steps.saved, "done");
    assert.equal(outcome.stoppedAt, "harness");
    assert.equal(outcome.complete, false);
    assert.equal(calls.save, 1);
  });

  it("a save failure stops at saved", async () => {
    const { deps } = makeDeps({
      saveRun: async () => {
        throw new Error("db gone");
      },
    });
    const outcome = await runAdjudicationChain(baseCtx(), deps);
    assert.equal(outcome.steps.saved, "failed");
    assert.equal(outcome.stoppedAt, "saved");
    assert.equal(outcome.complete, false);
    assert.equal(outcome.saveError, "db gone");
  });

  it("review + run reuse completes with reused steps", async () => {
    const digest = pocRunKey("scan-1:0", TEST_SNIPPET).digest;
    const { deps } = makeDeps({
      listRuns: async () => [
        { id: "poc:scan-1:0:x", status: "passed", sourceDigest: digest, output: "stored", durationMs: 7, createdAt: "2026-10-23T00:00:00Z" },
      ],
    });
    const outcome = await runAdjudicationChain(
      baseCtx({ aiReview: { threatModelReport: "r", foundryTestCode: "", economicRiskSummary: "", source: "openrouter" as const } }),
      deps,
    );
    assert.deepEqual(outcome.steps, { fetch: "done", llm: "reused", harness: "reused", saved: "reused" });
    assert.equal(outcome.complete, true);
    assert.equal(outcome.stoppedAt, null);
  });

  it("an empty body stops at fetch (LLM skipped) while the harness still runs", async () => {
    const { deps, calls } = makeDeps();
    const outcome = await runAdjudicationChain(baseCtx({ body: "" }), deps);
    assert.equal(outcome.steps.fetch, "failed");
    assert.equal(outcome.steps.llm, "skipped");
    assert.equal(outcome.stoppedAt, "fetch");
    assert.equal(outcome.complete, false);
    assert.equal(calls.run, 1);
    assert.equal(outcome.verdict, "passed");
  });

  it("an already-adjudicated finding is complete with every step skipped", async () => {
    const { deps } = makeDeps();
    const outcome = await runAdjudicationChain(
      baseCtx({
        disposition: { findingId: "scan-1:0", disposition: "confirmed" as const, note: null, updatedAt: "2026-10-23T00:00:00Z" },
      }),
      deps,
    );
    assert.equal(outcome.kind, "already_adjudicated");
    assert.deepEqual(outcome.steps, { fetch: "done", llm: "skipped", harness: "skipped", saved: "skipped" });
    assert.equal(outcome.complete, true);
    assert.equal(outcome.stoppedAt, null);
  });

  it("no target address stops at harness with saved skipped", async () => {
    const { deps } = makeDeps();
    const outcome = await runAdjudicationChain(baseCtx({ targetAddress: null }), deps);
    assert.equal(outcome.steps.harness, "failed");
    assert.equal(outcome.steps.saved, "skipped");
    assert.equal(outcome.stoppedAt, "harness");
    assert.equal(outcome.complete, false);
  });
});
