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

// Distinct-code variants: tests whose subject is per-run sequencing
// (breaker) or independent runs need findings whose prepared
// PoC code DIFFERS — identical code now dedupes within an entry
// (identical-draft dedupe, see the dedupe suite below), which would
// silently turn their later findings into shared saves.
const snippetWithTest = (fn: string) => `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "forge-std/Test.sol";
contract PoC is Test {
    function ${fn}() public { assertTrue(true); }
}`;
const TEST_SNIPPET_B = snippetWithTest("test_exploit_b");
const TEST_SNIPPET_C = snippetWithTest("test_exploit_c");
const TEST_SNIPPET_D = snippetWithTest("test_exploit_d");
const TEST_SNIPPET_E = snippetWithTest("test_exploit_e");

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

const OPTS: AutoPocOptions = { backendUrl: "http://127.0.0.1:8787", enabled: true };
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
      // Distinct code for the second finding: this case pins two
      // INDEPENDENT runs (identical code would dedupe to one backend
      // call + a shared save — the dedupe suite below covers that).
      const report = makeReport([
        makeFinding(),
        makeFinding({ title: "Second", detector: "access", exploitSolidity: TEST_SNIPPET_B }),
      ]);
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

  it("a finding whose snippet cannot become a test is not attempted", () => {
    // prepareFindingPoc returns null for a snippet with no contract, an
    // interface-only snippet, or a bare attack contract the wrapper rejects.
    // Measured before this filter: 209 of 518 attempts ended as no_tests and the
    // one-repair rescue recovered none, so those attempts bought nothing.
    // The fallback selector is broader than it first looks: a detector without
    // its own harness inherits its SmartBugs-category templates, so an
    // unwrappable snippet is usually rescued and honestly reports unadapted if
    // the template's TODOs are unfilled. prepareFindingPoc therefore returns null
    // for exactly two cases — an empty snippet, and a detector on the
    // not-PoC-able list (no on-chain exploit exists, so any verdict would be
    // unearned). Both are excluded here.
    const report = makeReport([
      makeFinding({ title: "Empty snippet", detector: "access", exploitSolidity: "" }),
      // Unwrappable snippet AND a detector on the not-PoC-able list: no template
      // is offered, so there is nothing to run.
      makeFinding({ title: "Not PoC-able", detector: "registry-dispatched-logic", exploitSolidity: "interface IVictim { function go() external; }" }),
      makeFinding({ title: "Preparable", detector: "access", exploitSolidity: TEST_SNIPPET }),
    ]);
    const selected = selectAutoPocFindings(report, "contract V {}");
    assert.deepEqual(
      selected.map((c) => c.finding.title),
      ["Preparable"],
      "only the finding with a runnable PoC is attempted",
    );
  });

  it("(d) there is no attempt cap: every finding in every entry is attempted", async () => {
    // Removed 2026-10-27. The cap (default 25 backend attempts per run) was a
    // silent recall ceiling — every flagged finding past the 25th kept a
    // static-only record. This test used to assert the cap stopped at 2; it now
    // asserts the opposite, including across entries, because a cap that
    // resets per entry would be just as quiet a ceiling.
    const { deps, calls, logs } = makeDeps();
    const state = newAutoPocRunState();
    const report = makeReport([
      makeFinding(),
      makeFinding({ title: "Two", detector: "access", exploitSolidity: TEST_SNIPPET_B }),
      makeFinding({ title: "Three", detector: "overflow", exploitSolidity: TEST_SNIPPET_C }),
    ]);

    const res = await runAutoPocForEntry(state, entry(report), OPTS, deps);
    assert.equal(res.attempted, 3);
    assert.equal(calls.backend, 3);

    const res2 = await runAutoPocForEntry(state, entry(report, "scan-2"), OPTS, deps);
    assert.equal(res2.attempted, 3, "the second entry is attempted in full too");
    assert.equal(calls.backend, 6);
    assert.equal(logs.filter((l) => l.includes("cap reached")).length, 0);
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
    // Distinct code per finding: the fake backend's outcome sequence
    // is keyed on real backend calls, and identical code would
    // dedupe (a cached "passed" would replace the scripted outcome).
    const five = makeReport([
      makeFinding(),
      makeFinding({ title: "2", detector: "d2", exploitSolidity: TEST_SNIPPET_B }),
      makeFinding({ title: "3", detector: "d3", exploitSolidity: TEST_SNIPPET_C }),
      makeFinding({ title: "4", detector: "d4", exploitSolidity: TEST_SNIPPET_D }),
      makeFinding({ title: "5", detector: "d5", exploitSolidity: TEST_SNIPPET_E }),
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
    // Distinct code per finding: identical code would share the
    // first compile error (compile outcomes ARE shared — see the
    // dedupe suite), collapsing four attempts into one.
    const report = makeReport([
      makeFinding(),
      makeFinding({ title: "2", detector: "d2", exploitSolidity: TEST_SNIPPET_B }),
      makeFinding({ title: "3", detector: "d3", exploitSolidity: TEST_SNIPPET_C }),
      makeFinding({ title: "4", detector: "d4", exploitSolidity: TEST_SNIPPET_D }),
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

describe("auto-PoC identical-draft dedupe", () => {
  it("two findings, identical generated code → ONE backend call, both saved, sibling marked shared", async () => {
    const { deps, calls, saved } = makeDeps();
    const state = newAutoPocRunState();
    // Both findings carry the same exploitSolidity (makeFinding's
    // default): the prepared PoC code is byte-identical — Jer's live
    // shape (10 same-detector siblings, 10 identical drafts).
    const report = makeReport([
      makeFinding(),
      makeFinding({ title: "Same code, second finding", detector: "access" }),
    ]);
    const res = await runAutoPocForEntry(state, entry(report), OPTS, deps);
    assert.equal(calls.backend, 1);
    assert.equal(saved.length, 2);
    assert.equal(saved[0]!.findingId, "scan-1:0");
    assert.equal(saved[1]!.findingId, "scan-1:1");
    assert.equal(saved[1]!.status, "passed");
    // The sibling's record is distinguishable from an independent
    // run: its output names the shared run and the finding that ran.
    assert.match(saved[1]!.output, /shared run — identical PoC code \(SHA-256 [0-9a-f]{64}\)/);
    assert.match(saved[1]!.output, /finding scan-1:0/);
    assert.doesNotMatch(saved[0]!.output, /shared run/);
    // Verdicts land on both findings; the accounting splits the one
    // backend attempt from the one shared save.
    assert.equal(res.passed, 2);
    assert.equal(res.attempted, 1);
    assert.equal(res.shared, 1);
    assert.equal(state.tally.attempted, 1);
    assert.equal(state.tally.shared, 1);
    assert.match(res.note, /1 shared/);
  });

  it("two findings, different code → two backend calls, nothing shared", async () => {
    const { deps, calls, saved } = makeDeps();
    const state = newAutoPocRunState();
    const report = makeReport([
      makeFinding(),
      makeFinding({ title: "Other code", detector: "access", exploitSolidity: TEST_SNIPPET_B }),
    ]);
    const res = await runAutoPocForEntry(state, entry(report), OPTS, deps);
    assert.equal(calls.backend, 2);
    assert.equal(res.attempted, 2);
    assert.equal(res.shared, 0);
    assert.doesNotMatch(saved[1]!.output, /shared run/);
  });

  it("a shared save does not consume a backend run", async () => {
    const { deps, calls, saved } = makeDeps();
    const state = newAutoPocRunState();
    const report = makeReport([
      makeFinding(),
      makeFinding({ title: "Identical twin", detector: "access" }),
      makeFinding({ title: "Other code", detector: "overflow", exploitSolidity: TEST_SNIPPET_B }),
    ]);
    const res = await runAutoPocForEntry(state, entry(report), OPTS, deps);
    // A ran, its identical twin shared without a backend call, and the
    // different-code finding got its own run: three verdicts, two runs.
    assert.equal(calls.backend, 2);
    assert.equal(saved.length, 3);
    assert.equal(res.attempted, 2);
    assert.equal(res.shared, 1);
    assert.equal(res.passed, 3);
  });

  it("a compile-error outcome is shared too — it is a property of the code alone", async () => {
    // The runBackend override replaces the counting default, so it
    // keeps its own count.
    let backendCalls = 0;
    const { deps, saved } = makeDeps({
      runBackend: async () => {
        backendCalls++;
        return {
          status: "error",
          logs: "Compiler run failed: ParserError: expected identifier",
          durationMs: 5,
        };
      },
      repair: async () => {
        throw new Error("no key");
      },
    });
    const state = newAutoPocRunState();
    const report = makeReport([
      makeFinding(),
      makeFinding({ title: "Identical twin", detector: "access" }),
    ]);
    const res = await runAutoPocForEntry(state, entry(report), OPTS, deps);
    assert.equal(backendCalls, 1);
    assert.equal(res.errors, 2);
    assert.equal(res.attempted, 1);
    assert.equal(res.shared, 1);
    assert.equal(saved[1]!.status, "error");
    assert.match(saved[1]!.output, /shared run/);
    // A shared compile error is not infra — the breaker stays shut.
    assert.equal(state.breakerTripped, false);
    assert.equal(state.consecutiveInfra, 0);
  });

  it("infra outcomes are never shared — an unreachable backend is attempted per finding", async () => {
    let backendCalls = 0;
    const { deps } = makeDeps({
      runBackend: async () => {
        backendCalls++;
        return {
          status: "backend_unreachable",
          logs: "Backend not reachable — start it in Termux",
          durationMs: 0,
        };
      },
    });
    const state = newAutoPocRunState();
    const report = makeReport([
      makeFinding(),
      makeFinding({ title: "Identical twin", detector: "access" }),
    ]);
    const res = await runAutoPocForEntry(state, entry(report), OPTS, deps);
    // backend_unreachable carries no information about the code, so
    // nothing is cached: both findings make their own real attempt
    // (and both count toward the circuit breaker, as before).
    assert.equal(backendCalls, 2);
    assert.equal(res.shared, 0);
    assert.equal(res.errors, 2);
  });
});
