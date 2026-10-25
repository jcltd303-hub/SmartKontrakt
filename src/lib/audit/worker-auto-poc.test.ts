// src/lib/audit/worker-auto-poc.test.ts
//
// Auto-PoC orchestration for the pipeline worker
// (pipeline-worker/auto-poc.ts): Jer's rule — an entry whose initial
// pipeline scores include a high or critical finding gets an automatic
// adjudication-chain run (LLM-gen -> Foundry -> save) per eligible
// finding. These tests drive the REAL chain with fake leaf deps
// (review / repair / backend / persist), the same pattern as
// adjudicate-chain.test.ts: no DB, no OpenRouter, no backend process.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runAdjudicationChain } from "./adjudicate-chain.ts";
import {
  runAutoPocForEntry,
  selectAutoPocFindings,
  newAutoPocRunState,
  autoPocCapReached,
  type AutoPocDeps,
  type AutoPocOptions,
} from "../../../pipeline-worker/auto-poc.ts";
import type { Finding, Report } from "./types.ts";

const TEST_SNIPPET = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "forge-std/Test.sol";
contract PoC is Test {
    function test_exploit() public { assertTrue(true); }
}`;

// A complete Test contract whose only test function is private —
// forge executes none of it, so the chain's generation gate fires.
const PRIVATE_TEST_SNIPPET = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "forge-std/Test.sol";
contract PoC is Test {
    function test_exploit() private { assertTrue(true); }
}`;

const SOURCE_BODY = `contract Vault {
    function withdraw() external { msg.sender.call{value: 1 ether}(""); }
}`;

function makeFinding(partial: Partial<Finding> = {}): Finding {
  return {
    id: "in-report",
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

function makeReport(findings: Finding[]): Report {
  return {
    label: "Vault",
    inputKind: "source",
    riskScore: 90,
    summary: "Vault: findings",
    inventory: { selectors: [], topics: [], notes: [] } as unknown as Report["inventory"],
    findings,
    aiNarrative: null,
    aiStatus: "unavailable",
  } as Report;
}

type SavedRecord = Parameters<AutoPocDeps["saveRun"]>[0];

function makeDeps(overrides: Partial<AutoPocDeps> = {}) {
  const calls = { review: 0, persistReview: 0, repair: 0, backend: 0, save: 0, list: 0 };
  const saved: SavedRecord[] = [];
  const logs: string[] = [];
  const deps: AutoPocDeps = {
    runChain: runAdjudicationChain,
    generateReview: async () => {
      calls.review++;
      return {
        threatModelReport: "review",
        foundryTestCode: "",
        economicRiskSummary: "",
        source: "openrouter" as const,
      };
    },
    persistReview: async () => {
      calls.persistReview++;
    },
    repair: async () => {
      calls.repair++;
      return { fixedCode: TEST_SNIPPET };
    },
    runBackend: async () => {
      calls.backend++;
      return { status: "passed", logs: "1 passed; 0 failed", durationMs: 10 };
    },
    saveRun: async (record) => {
      calls.save++;
      saved.push(record);
    },
    listRuns: async () => {
      calls.list++;
      return [];
    },
    log: (line) => {
      logs.push(line);
    },
    ...overrides,
  };
  return { deps, calls, saved, logs };
}

const OPTS: AutoPocOptions = { backendUrl: "http://127.0.0.1:8787", cap: 25, enabled: true };
const entry = (report: Report, scanId = "scan-1") => ({
  scanId,
  address: "0x3dfd23a6c5e8bbcfc9581d2e864a68feb6a076d3",
  chainId: "ethereum",
  report,
  body: SOURCE_BODY,
});

describe("auto-PoC trigger + eligibility (selectAutoPocFindings)", () => {
  it("(a) fires for high and for critical findings", () => {
    const report = makeReport([
      makeFinding({ severity: "high", title: "High one" }),
      makeFinding({ severity: "critical", title: "Crit one" }),
    ]);
    const picked = selectAutoPocFindings(report, SOURCE_BODY);
    assert.deepEqual(picked.map((p) => p.ord), [0, 1]);
  });

  it("(a) does not fire for medium/low/info-only reports", () => {
    const report = makeReport([
      makeFinding({ severity: "medium" }),
      makeFinding({ severity: "low", title: "Low one" }),
      makeFinding({ severity: "info", title: "Info one" }),
    ]);
    assert.equal(selectAutoPocFindings(report, SOURCE_BODY).length, 0);
  });

  it("(b) presence-only uncorroborated findings are skipped; corroborated ones run", () => {
    const presence = makeFinding({
      detector: "bytecode-delegatecall",
      title: "DELEGATECALL executes foreign code in this contract's storage",
      locationFn: "runtime",
      snippet: "  00a3  DELEGATECALL",
    });
    const report = makeReport([presence]);
    assert.equal(selectAutoPocFindings(report, SOURCE_BODY).length, 0);

    const corroborated = makeReport([{ ...presence, corroborated: true }]);
    assert.equal(selectAutoPocFindings(corroborated, SOURCE_BODY).length, 1);

    // G3 source branch: the analyzed body itself carries the call site.
    const sourceCorroborated = makeReport([presence]);
    const bodyWithCallSite = "contract P { function f(address t) external { t.delegatecall(''); } }";
    assert.equal(selectAutoPocFindings(sourceCorroborated, bodyWithCallSite).length, 1);
  });

  it("(c) a finding that already carries a verdict is skipped", () => {
    const report = makeReport([makeFinding({ pocStatus: "passed" })]);
    assert.equal(selectAutoPocFindings(report, SOURCE_BODY).length, 0);
  });
});

describe("runAutoPocForEntry", () => {
  it("(a) runs the chain for a high finding and for a critical finding", async () => {
    for (const severity of ["high", "critical"] as const) {
      const { deps, calls } = makeDeps();
      const state = newAutoPocRunState();
      const res = await runAutoPocForEntry(state, entry(makeReport([makeFinding({ severity })])), OPTS, deps);
      assert.equal(res.attempted, 1, severity);
      assert.equal(calls.backend, 1, severity);
      assert.equal(res.passed, 1, severity);
    }
  });

  it("(a) a medium/low-only entry attempts nothing and calls nothing", async () => {
    const { deps, calls } = makeDeps();
    const state = newAutoPocRunState();
    const res = await runAutoPocForEntry(
      state,
      entry(makeReport([makeFinding({ severity: "medium" }), makeFinding({ severity: "low", title: "L" })])),
      OPTS,
      deps,
    );
    assert.equal(res.attempted, 0);
    assert.equal(calls.backend, 0);
    assert.equal(calls.save, 0);
    assert.equal(calls.review, 0);
  });

  it("(f) a full fake run saves the verdict through the persist dep — passed and failed", async () => {
    // passed
    {
      const { deps, saved, calls } = makeDeps();
      const state = newAutoPocRunState();
      const report = makeReport([makeFinding(), makeFinding({ title: "Second", detector: "access" })]);
      const res = await runAutoPocForEntry(state, entry(report), OPTS, deps);
      assert.equal(res.attempted, 2);
      assert.equal(res.passed, 2);
      assert.equal(saved.length, 2);
      assert.equal(saved[0]!.status, "passed");
      assert.equal(saved[0]!.findingId, "scan-1:0");
      assert.equal(saved[1]!.findingId, "scan-1:1");
      assert.match(saved[0]!.output, /1 passed; 0 failed/);
      // The scan-level review is generated ONCE for the entry and
      // persisted once — the second finding reuses it.
      assert.equal(calls.review, 1);
      assert.equal(calls.persistReview, 1);
      assert.equal(state.tally.passed, 2);
    }
    // failed
    {
      const { deps, saved } = makeDeps({
        runBackend: async () => ({
          status: "failed",
          logs: "[FAIL: test_exploit] assertion failed\n0 passed; 1 failed",
          durationMs: 12,
        }),
      });
      const state = newAutoPocRunState();
      const res = await runAutoPocForEntry(state, entry(makeReport([makeFinding()])), OPTS, deps);
      assert.equal(res.failed, 1);
      assert.equal(saved.length, 1);
      assert.equal(saved[0]!.status, "failed");
      assert.match(saved[0]!.output, /0 passed; 1 failed/);
    }
  });

  it("(g) a test-less draft saves no_tests WITHOUT calling the backend", async () => {
    const { deps, calls, saved } = makeDeps({
      // The LLM generation attempt throws (no key / model down): the
      // module's repair adapter degrades to "no source", the gate
      // still saves the honest no_tests outcome.
      repair: async () => {
        throw new Error("OPENROUTER_API_KEY is not set");
      },
    });
    const state = newAutoPocRunState();
    const report = makeReport([makeFinding({ exploitSolidity: PRIVATE_TEST_SNIPPET })]);
    const res = await runAutoPocForEntry(state, entry(report), OPTS, deps);
    assert.equal(calls.backend, 0);
    assert.equal(saved.length, 1);
    assert.equal(saved[0]!.status, "no_tests");
    assert.equal(res.skipped, 1);
    assert.equal(res.errors, 0);
    assert.equal(state.consecutiveInfra, 0);
  });

  it("(d) the per-run cap is enforced and logged once", async () => {
    const { deps, calls, logs } = makeDeps();
    const state = newAutoPocRunState();
    const opts = { ...OPTS, cap: 2 };
    const report = makeReport([
      makeFinding(),
      makeFinding({ title: "Two", detector: "access" }),
      makeFinding({ title: "Three", detector: "overflow" }),
    ]);
    const res = await runAutoPocForEntry(state, entry(report), opts, deps);
    assert.equal(res.attempted, 2);
    assert.equal(calls.backend, 2);
    assert.equal(autoPocCapReached(state, 2), true);
    assert.equal(logs.filter((l) => l.includes("cap reached")).length, 1);
    // Next entry: nothing attempted, no second cap log line.
    const res2 = await runAutoPocForEntry(state, entry(report, "scan-2"), opts, deps);
    assert.equal(res2.attempted, 0);
    assert.equal(calls.backend, 2);
    assert.equal(logs.filter((l) => l.includes("cap reached")).length, 1);
  });

  it("(e) circuit breaker: 3 consecutive infra failures trip it; entries still complete", async () => {
    const { deps, calls, logs } = makeDeps({
      runBackend: async () => ({
        status: "backend_unreachable",
        logs: "Backend not reachable — start it in Termux",
        durationMs: 0,
      }),
    });
    const state = newAutoPocRunState();
    const twoFindings = () =>
      makeReport([makeFinding(), makeFinding({ title: "Two", detector: "access" })]);

    const r1 = await runAutoPocForEntry(state, entry(twoFindings(), "scan-1"), OPTS, deps);
    assert.equal(r1.errors, 2);
    assert.equal(state.breakerTripped, false);

    // Third consecutive infra outcome trips the breaker mid-entry;
    // the entry's second finding is never attempted, and the call
    // returns normally (the pipeline entry completes).
    const r2 = await runAutoPocForEntry(state, entry(twoFindings(), "scan-2"), OPTS, deps);
    assert.equal(r2.attempted, 1);
    assert.equal(r2.errors, 1);
    assert.equal(state.breakerTripped, true);
    assert.equal(state.tally.errors, 3);

    // Later entries are no-ops; the breaker log line fires once.
    const before = calls.backend;
    const r3 = await runAutoPocForEntry(state, entry(twoFindings(), "scan-3"), OPTS, deps);
    assert.equal(r3.attempted, 0);
    assert.equal(calls.backend, before);
    assert.equal(logs.filter((l) => l.includes("circuit breaker")).length, 1);
  });

  it("(e) a non-infra outcome resets the consecutive-infra counter", async () => {
    let n = 0;
    const { deps } = makeDeps({
      runBackend: async () => {
        n++;
        // infra, infra, passed, infra, infra — never 3 in a row.
        if (n === 3) return { status: "passed", logs: "1 passed; 0 failed", durationMs: 5 };
        return { status: "backend_unreachable", logs: "Backend not reachable", durationMs: 0 };
      },
    });
    const state = newAutoPocRunState();
    const five = makeReport([
      makeFinding(),
      makeFinding({ title: "2", detector: "d2" }),
      makeFinding({ title: "3", detector: "d3" }),
      makeFinding({ title: "4", detector: "d4" }),
      makeFinding({ title: "5", detector: "d5" }),
    ]);
    const res = await runAutoPocForEntry(state, entry(five), OPTS, deps);
    assert.equal(res.attempted, 5);
    assert.equal(res.errors, 4);
    assert.equal(res.passed, 1);
    assert.equal(state.breakerTripped, false);
    assert.equal(state.consecutiveInfra, 2);
  });

  it("(e) compile errors are errors but NOT infra — they never trip the breaker", async () => {
    const { deps } = makeDeps({
      runBackend: async () => ({
        status: "error",
        logs: "Compiler run failed: ParserError: expected identifier",
        durationMs: 5,
      }),
      repair: async () => {
        throw new Error("no key");
      },
    });
    const state = newAutoPocRunState();
    const report = makeReport([
      makeFinding(),
      makeFinding({ title: "2", detector: "d2" }),
      makeFinding({ title: "3", detector: "d3" }),
      makeFinding({ title: "4", detector: "d4" }),
    ]);
    const res = await runAutoPocForEntry(state, entry(report), OPTS, deps);
    assert.equal(res.attempted, 4);
    assert.equal(res.errors, 4);
    assert.equal(state.breakerTripped, false);
    assert.equal(state.consecutiveInfra, 0);
  });

  it("(h) enabled:false disables entirely — no chain, backend, save or review calls", async () => {
    const { deps, calls } = makeDeps();
    const state = newAutoPocRunState();
    const res = await runAutoPocForEntry(
      state,
      entry(makeReport([makeFinding()])),
      { ...OPTS, enabled: false },
      deps,
    );
    assert.equal(res.attempted, 0);
    assert.equal(res.note, "disabled");
    assert.deepEqual(calls, { review: 0, persistReview: 0, repair: 0, backend: 0, save: 0, list: 0 });
    assert.equal(state.tally.attempted, 0);
  });

  it("a failed generation (repair yields a runnable PoC) still runs and saves honestly", async () => {
    // Generation succeeds via the gate: draft has no executable test,
    // the repair dep supplies one, the backend runs THAT source.
    const { deps, calls, saved } = makeDeps();
    const state = newAutoPocRunState();
    const report = makeReport([makeFinding({ exploitSolidity: PRIVATE_TEST_SNIPPET })]);
    const res = await runAutoPocForEntry(state, entry(report), OPTS, deps);
    assert.equal(calls.repair, 1);
    assert.equal(calls.backend, 1);
    assert.equal(res.passed, 1);
    assert.equal(saved[0]!.status, "passed");
  });
});
