// src/lib/audit/adjudication.test.ts
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  aiReviewExcerptForFinding,
  dedupeRecentFindings,
  findingFeedIdentityKey,
  hasVulnCorroboration,
  isPresenceOnlyFinding,
  partitionPocAuditFindings,
  planAdjudication,
  pocAuditEligibility,
  pocOutputDisclosesAttempt,
  prepareFindingPoc,
  sourceCorroboratesPresence,
  suggestDispositionForVerdict,
} from "./adjudication.ts";

describe("suggestDispositionForVerdict", () => {
  it("maps a reproduced verdict to confirmed", () => {
    assert.equal(suggestDispositionForVerdict("passed"), "confirmed");
  });

  // G6 changed this mapping: "failed" used to suggest false_positive
  // unconditionally. A not-reproduced run is only worth that suggestion
  // when the attempt was target-tailored AND its output discloses what
  // was tried — the cases below pin each side of the condition.
  it("a bare failed verdict (no provenance supplied) suggests needs_more_info, not false_positive", () => {
    assert.equal(suggestDispositionForVerdict("failed"), "needs_more_info");
    assert.equal(suggestDispositionForVerdict("failed", {}), "needs_more_info");
    assert.equal(suggestDispositionForVerdict("failed", { origin: null, output: null }), "needs_more_info");
  });

  it("failed + generated PoC + an output that discloses the attempt suggests false_positive", () => {
    const forgeLog = "Ran 1 test for test/Exploit.t.sol:PoC\n[FAIL: assertion failed] test_drain() (gas: 12345)";
    assert.equal(
      suggestDispositionForVerdict("failed", { origin: "generated", output: forgeLog }),
      "false_positive",
    );
    const triedLog = "exploit did not reproduce: balance unchanged. Tried withdraw(), claim().";
    assert.equal(
      suggestDispositionForVerdict("failed", { origin: "generated", output: triedLog }),
      "false_positive",
    );
  });

  it("failed + library template suggests needs_more_info even when its output discloses the attempt", () => {
    // The template's own disclosure is the generic shape list it tried;
    // its failure text says the real entry point may be named
    // differently — that is not evidence the finding is false.
    const templateLog =
      "no payout selector moved ETH out of the target. Tried withdraw(), claim(), drain(). This does NOT establish safety.";
    assert.equal(
      suggestDispositionForVerdict("failed", { origin: "template", output: templateLog }),
      "needs_more_info",
    );
  });

  it("failed + generated PoC + an output that discloses nothing suggests needs_more_info", () => {
    assert.equal(
      suggestDispositionForVerdict("failed", { origin: "generated", output: "" }),
      "needs_more_info",
    );
    assert.equal(
      suggestDispositionForVerdict("failed", { origin: "generated", output: "run finished" }),
      "needs_more_info",
    );
  });

  it("maps non-verdicts to needs_more_info — an error is not evidence", () => {
    assert.equal(suggestDispositionForVerdict("error"), "needs_more_info");
    assert.equal(suggestDispositionForVerdict(null), "needs_more_info");
  });

  it("maps no_tests and skipped to needs_more_info — neither is evidence about the bug", () => {
    // no_tests: generation produced no executable test function.
    // skipped: the target holds no value at stake. Both are terminal
    // outcome kinds, distinct from "error", with the same suggestion.
    assert.equal(suggestDispositionForVerdict("no_tests"), "needs_more_info");
    assert.equal(suggestDispositionForVerdict("skipped"), "needs_more_info");
  });
});

describe("pocOutputDisclosesAttempt (G6)", () => {
  it("recognizes the templates' tried-selectors disclosure and forge failure lines", () => {
    assert.equal(pocOutputDisclosesAttempt("Tried withdraw(), claim(), drain()"), true);
    assert.equal(pocOutputDisclosesAttempt("[FAIL: revert] test_exploit() (gas: 1)"), true);
    assert.equal(pocOutputDisclosesAttempt("exploit did not reproduce: drained <= deposit"), true);
    // Forge's result summary — the tail of the same attempt log.
    assert.equal(pocOutputDisclosesAttempt("0 passed; 1 failed"), true);
    assert.equal(pocOutputDisclosesAttempt("Suite result: FAILED. 0 passed; 2 failed; 0 skipped"), true);
    // A passing/all-skipped summary evidences no failed attempt.
    assert.equal(pocOutputDisclosesAttempt("1 passed; 0 failed"), false);
  });

  it("empty or content-free output discloses nothing", () => {
    assert.equal(pocOutputDisclosesAttempt(null), false);
    assert.equal(pocOutputDisclosesAttempt(undefined), false);
    assert.equal(pocOutputDisclosesAttempt(""), false);
    assert.equal(pocOutputDisclosesAttempt("   \n"), false);
    assert.equal(pocOutputDisclosesAttempt("Suite result: ok"), false);
  });
});

describe("planAdjudication — the idempotency matrix", () => {
  const run = { digest: "abc", status: "passed" };

  it("skips everything when a disposition exists (no redo)", () => {
    const plan = planAdjudication({
      hasDisposition: true,
      hasReview: false,
      candidateDigest: "abc",
      existingRuns: [run],
    });
    assert.equal(plan.alreadyAdjudicated, true);
  });

  it("force overrides the disposition skip AND the run reuse, but still reuses the scan's review", () => {
    const plan = planAdjudication({
      hasDisposition: true,
      hasReview: true,
      candidateDigest: "abc",
      existingRuns: [run],
      force: true,
    });
    assert.equal(plan.alreadyAdjudicated, false);
    assert.equal(plan.reuseRun, null);
    assert.equal(plan.reuseReview, true);
  });

  it("reuses an existing review (no second OpenRouter call for the scan)", () => {
    const plan = planAdjudication({
      hasDisposition: false,
      hasReview: true,
      candidateDigest: "zzz",
      existingRuns: [],
    });
    assert.equal(plan.reuseReview, true);
    assert.equal(plan.alreadyAdjudicated, false);
  });

  it("reuses a terminal run whose digest matches the candidate PoC", () => {
    const plan = planAdjudication({
      hasDisposition: false,
      hasReview: false,
      candidateDigest: "abc",
      existingRuns: [{ digest: "other", status: "passed" }, run],
    });
    assert.deepEqual(plan.reuseRun, run);
  });

  it("reuses stored no_tests and skipped runs for the same digest (terminal outcome kinds)", () => {
    for (const status of ["no_tests", "skipped"]) {
      const plan = planAdjudication({
        hasDisposition: false,
        hasReview: false,
        candidateDigest: "abc",
        existingRuns: [{ digest: "abc", status }],
      });
      assert.deepEqual(plan.reuseRun, { digest: "abc", status });
    }
  });

  it("does not reuse a run for a different digest, a non-terminal status, or a null candidate", () => {
    assert.equal(
      planAdjudication({ hasDisposition: false, hasReview: false, candidateDigest: "nope", existingRuns: [run] }).reuseRun,
      null,
    );
    assert.equal(
      planAdjudication({
        hasDisposition: false,
        hasReview: false,
        candidateDigest: "abc",
        existingRuns: [{ digest: "abc", status: "running" }],
      }).reuseRun,
      null,
    );
    assert.equal(
      planAdjudication({ hasDisposition: false, hasReview: false, candidateDigest: null, existingRuns: [run] }).reuseRun,
      null,
    );
  });

  it("plans a full fresh run when nothing exists yet", () => {
    const plan = planAdjudication({
      hasDisposition: false,
      hasReview: false,
      candidateDigest: "abc",
      existingRuns: [],
    });
    assert.deepEqual(plan, { alreadyAdjudicated: false, reuseReview: false, reuseRun: null });
  });
});

describe("prepareFindingPoc", () => {
  it("passes a complete Foundry test through unchanged", () => {
    const test = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "forge-std/Test.sol";
contract PoC is Test {
    function test_exploit() public { assertTrue(true); }
}`;
    const prepared = prepareFindingPoc({ exploitSolidity: test, severity: "critical", detector: "custom" });
    assert.ok(prepared);
    assert.equal(prepared.testCode, test);
    // The finding's own code is finding-specific: origin "generated" (G6).
    assert.equal(prepared.origin, "generated");
  });

  it("wraps an attack-contract snippet into a runnable PoC test", () => {
    const snippet = `contract VaultExploit {
    function attack() external payable {}
}`;
    const prepared = prepareFindingPoc({ exploitSolidity: snippet, severity: "critical", detector: "reentrancy" });
    assert.ok(prepared);
    assert.ok(prepared.testCode.includes("contract PoC is Test"));
    assert.equal(prepared.source, snippet);
    assert.equal(prepared.origin, "generated");
  });

  it("falls back to the detector-class template when the finding has no snippet", () => {
    const prepared = prepareFindingPoc({ exploitSolidity: "", severity: "critical", detector: "reentrancy" });
    assert.ok(prepared);
    assert.ok(prepared.testCode.includes("contract PoC is Test"));
    assert.ok(prepared.source.length > 0);
    // The library fallback is the one "template"-origin preparation (G6).
    assert.equal(prepared.origin, "template");
  });
});

describe("dedupeRecentFindings — re-scans of one address collapse to the latest scan's copy", () => {
  type Row = {
    id: string;
    scanId: string;
    detector: string;
    title: string;
    targetAddress?: string | null;
    pocStatus?: string | null;
  };
  const row = (partial: Partial<Row> & { id: string }): Row => ({
    scanId: "scan-1",
    detector: "unprotected-initializer",
    title: "initialize can be called by anyone, more than once",
    targetAddress: "0x3dfd23a6c5e8bbcfc9581d2e864a68feb6a076d3",
    ...partial,
  });

  it("collapses 18 re-scan copies (newest first) to the latest scan's row", () => {
    // Mirrors Jer's archive: one address, the same finding title once per
    // scan of that address. Input is newest-scan-first (the feed ORDER BY).
    const rows: Row[] = Array.from({ length: 18 }, (_, i) => {
      const n = 18 - i; // first row = scan 18, the newest
      return row({ id: `scan-${n}:0`, scanId: `scan-${n}`, pocStatus: n === 18 ? "failed" : null });
    });
    const out = dedupeRecentFindings(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].id, "scan-18:0");
    assert.equal(out[0].pocStatus, "failed");
  });

  it("keeps distinct titles, detectors, and addresses apart", () => {
    const rows = [
      row({ id: "a:0" }),
      row({ id: "a:1", title: "initialize delegatecalls a caller-supplied address", detector: "delegatecall" }),
      row({ id: "a:2", detector: "delegatecall" }), // same title as a:0, different detector
      row({ id: "b:0", scanId: "scan-9", targetAddress: "0xd803472c47a87d7b63e888de53f03b4191b846a8" }),
    ];
    assert.equal(dedupeRecentFindings(rows).length, 4);
  });

  it("collapses case variants of the same address/title", () => {
    const rows = [
      row({ id: "new:0", scanId: "new", targetAddress: "0x3DFD23A6C5E8BBCFC9581D2E864A68FEB6A076D3" }),
      row({ id: "old:0", scanId: "old" }),
    ];
    const out = dedupeRecentFindings(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].id, "new:0");
  });

  it("falls back to scan-scoped identity for address-less scans", () => {
    const base = { detector: "reentrancy", title: "Reentrant call", targetAddress: null };
    const rows = [
      { id: "s1:0", scanId: "s1", ...base },
      { id: "s1:1", scanId: "s1", ...base }, // same scan, detector repeated the finding
      { id: "s2:0", scanId: "s2", ...base }, // different pasted-source scan: kept
    ];
    const out = dedupeRecentFindings(rows);
    assert.deepEqual(out.map((r) => r.id), ["s1:0", "s2:0"]);
  });

  it("findingFeedIdentityKey is (address, detector, title) — no chain, no scan", () => {
    const key = findingFeedIdentityKey({
      scanId: "scan-x",
      detector: "Delegatecall",
      title: "  Invoke delegatecalls  ",
      targetAddress: "0xABC",
    });
    assert.equal(key, "addr:0xabc:delegatecall:invoke delegatecalls");
  });
});

describe("aiReviewExcerptForFinding", () => {
  const review = {
    threatModelReport:
      "The vault's accounting is broadly sound.\n\nThe reentrancy finding is real: withdraw() sends ETH before updating the ledger, so a malicious receiver can re-enter and drain repeat withdrawals.\n\nOverall the proxy setup is standard.",
    economicRiskSummary: "TVL at risk is the full vault balance.",
    foundryTestCode: "",
    source: "openrouter" as const,
  };

  it("returns the paragraph that discusses the finding", () => {
    const excerpt = aiReviewExcerptForFinding(review, { title: "Reentrant withdraw", detector: "reentrancy" });
    assert.ok(excerpt);
    assert.ok(excerpt.includes("withdraw() sends ETH"));
  });

  it("returns null when the review never mentions the finding", () => {
    assert.equal(aiReviewExcerptForFinding(review, { title: "Timestamp dependence", detector: "timestamp" }), null);
  });

  it("returns null for a missing review", () => {
    assert.equal(aiReviewExcerptForFinding(null, { title: "Reentrancy", detector: "reentrancy" }), null);
    assert.equal(aiReviewExcerptForFinding(undefined, { title: "Reentrancy", detector: "reentrancy" }), null);
  });
});

describe("actually-critical eligibility (presence-only rule)", () => {
  // The exact shape bytecode.ts emits: locationFn "runtime" and a
  // disassembly-window snippet around the opcode.
  const disasmSnippet = "  00a0  PUSH1 0x00\n> 00a3  DELEGATECALL\n  00a4  ISZERO";
  const presenceDelegatecall = {
    severity: "critical",
    detector: "bytecode-delegatecall",
    title: "DELEGATECALL executes foreign code in this contract's storage",
    locationFn: "runtime",
    snippet: disasmSnippet,
  };
  const presenceSelfdestruct = {
    severity: "high",
    detector: "bytecode-selfdestruct",
    title: "SELFDESTRUCT is reachable in the bytecode",
    locationFn: "runtime",
    snippet: "  00f0  CALLER\n> 00f1  SELFDESTRUCT",
  };
  const sourceReentrancy = {
    severity: "critical",
    detector: "reentrancy",
    title: "Reentrancy: state updated after external call",
    locationFn: "withdraw",
    snippet: "function withdraw() public { (bool ok,) = msg.sender.call{value: bal}(\"\"); balances[msg.sender] = 0; }",
  };
  const sourceHigh = { ...sourceReentrancy, severity: "high", title: "High reentrancy variant" };

  it("recognizes the presence family by detector and by title", () => {
    assert.equal(isPresenceOnlyFinding(presenceDelegatecall), true);
    assert.equal(isPresenceOnlyFinding(presenceSelfdestruct), true);
    assert.equal(
      isPresenceOnlyFinding({ detector: "other", title: "CALLCODE executes foreign code in this contract's storage" }),
      true,
    );
    assert.equal(isPresenceOnlyFinding({ detector: "other", title: "TIMESTAMP is read" }), true);
    assert.equal(isPresenceOnlyFinding(sourceReentrancy), false);
  });

  it("excludes presence-only findings with no corroboration, even at critical", () => {
    assert.deepEqual(pocAuditEligibility(presenceDelegatecall, "critical"), {
      eligible: false,
      exclusion: "presence_only",
    });
    // Presence is checked before severity/scope: widening to highs does
    // not resurrect an uncorroborated presence-only high either.
    assert.deepEqual(pocAuditEligibility(presenceSelfdestruct, "critical_and_high"), {
      eligible: false,
      exclusion: "presence_only",
    });
  });

  it("keeps a presence-family finding whose record carries a source-level call site", () => {
    const corroborated = {
      ...presenceDelegatecall,
      locationFn: "upgradeTo",
      snippet: "function upgradeTo(address impl) external { impl.delegatecall(upgradePayload); }",
    };
    assert.equal(hasVulnCorroboration(corroborated), true);
    assert.deepEqual(pocAuditEligibility(corroborated, "critical"), { eligible: true, exclusion: null });
  });

  it("keeps a presence-family finding with an explicit corroboration marker", () => {
    const marked = { ...presenceDelegatecall, corroborated: "target read from calldata at pc 0x1f3" };
    assert.equal(hasVulnCorroboration(marked), true);
    assert.equal(pocAuditEligibility(marked, "critical").eligible, true);
  });

  it("a disassembly snippet is not corroboration, even with a function name", () => {
    assert.equal(
      hasVulnCorroboration({ locationFn: "runtime", snippet: disasmSnippet }),
      false,
    );
    assert.equal(hasVulnCorroboration({ locationFn: null, snippet: "x.delegatecall(y)" }), false);
  });

  it("admits source-level criticals; highs wait for the widened scope", () => {
    assert.deepEqual(pocAuditEligibility(sourceReentrancy, "critical"), { eligible: true, exclusion: null });
    assert.deepEqual(pocAuditEligibility(sourceHigh, "critical"), { eligible: false, exclusion: "below_scope" });
    assert.deepEqual(pocAuditEligibility(sourceHigh, "critical_and_high"), { eligible: true, exclusion: null });
  });

  it("partition counts sum to the input and the excluded count is exact", () => {
    const rows = [
      sourceReentrancy, // eligible
      presenceDelegatecall, // presence-only
      presenceSelfdestruct, // presence-only (high, presence wins)
      sourceHigh, // below scope under "critical"
      { ...presenceDelegatecall, id: "marked", corroborated: true }, // eligible via marker
    ];
    const p = partitionPocAuditFindings(rows, "critical");
    assert.equal(p.eligible.length, 2);
    assert.equal(p.presenceOnlyExcluded.length, 2);
    assert.equal(p.belowScope.length, 1);
    assert.equal(
      p.eligible.length + p.presenceOnlyExcluded.length + p.belowScope.length,
      rows.length,
    );
    const wide = partitionPocAuditFindings(rows, "critical_and_high");
    assert.equal(wide.eligible.length, 3); // sourceHigh joins
    assert.equal(wide.presenceOnlyExcluded.length, 2);
    assert.equal(wide.belowScope.length, 0);
  });
});

describe("source corroboration (G3) — the presence escape hatch, revived", () => {
  // The exact shape bytecode.ts emits for a presence finding: locationFn
  // "runtime", a disassembly-window snippet. Before G3 this record could
  // NEVER be corroborated: nothing stamps the marker, and the snippet
  // heuristic rejects disassembly by construction.
  const disasmSnippet = "  00a0  PUSH1 0x00\n> 00a3  DELEGATECALL\n  00a4  ISZERO";
  const presenceDelegatecall = {
    severity: "critical",
    detector: "bytecode-delegatecall",
    title: "DELEGATECALL executes foreign code in this contract's storage",
    locationFn: "runtime",
    snippet: disasmSnippet,
  };
  const delegatecallSource = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract Vault {
    function upgradeTo(address impl, bytes calldata data) external {
        (bool ok, ) = impl.delegatecall(data);
        require(ok);
    }
}`;
  const plainSource = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract Plain {
    function pay(address to, uint256 amount) external {
        payable(to).transfer(amount);
    }
}`;

  it("(a) presence finding + source carrying the call site → corroborated and eligible", () => {
    assert.equal(hasVulnCorroboration(presenceDelegatecall, delegatecallSource), true);
    assert.deepEqual(pocAuditEligibility(presenceDelegatecall, "critical", delegatecallSource), {
      eligible: true,
      exclusion: null,
    });
  });

  it("(b) presence finding + source with NO call site for the construct → still excluded", () => {
    assert.equal(hasVulnCorroboration(presenceDelegatecall, plainSource), false);
    assert.deepEqual(pocAuditEligibility(presenceDelegatecall, "critical", plainSource), {
      eligible: false,
      exclusion: "presence_only",
    });
  });

  it("(c) regression: disassembly-window record + separate source with the call site → eligible through the partition", () => {
    // The real miss, shaped exactly: the stored record's own evidence
    // is a disassembly window; the corroborating evidence lives in the
    // contract's source, supplied per-row by the caller.
    const withSource = partitionPocAuditFindings([presenceDelegatecall], "critical", () => delegatecallSource);
    assert.equal(withSource.eligible.length, 1);
    assert.equal(withSource.presenceOnlyExcluded.length, 0);
    // The same record with no source supplied keeps the pre-G3 verdict.
    const without = partitionPocAuditFindings([presenceDelegatecall], "critical");
    assert.equal(without.eligible.length, 0);
    assert.equal(without.presenceOnlyExcluded.length, 1);
    // And a shared (non-resolver) source argument works for single-scan rows.
    const shared = partitionPocAuditFindings([presenceDelegatecall], "critical", delegatecallSource);
    assert.equal(shared.eligible.length, 1);
  });

  it("the per-family patterns mirror the source detectors — and only their own family corroborates", () => {
    const selfdestructFinding = { detector: "bytecode-selfdestruct", title: "SELFDESTRUCT is reachable in the bytecode" };
    assert.equal(
      sourceCorroboratesPresence(selfdestructFinding, "function close() external { selfdestruct(payable(msg.sender)); }"),
      true,
    );
    // A delegatecall site does NOT corroborate a selfdestruct finding.
    assert.equal(sourceCorroboratesPresence(selfdestructFinding, delegatecallSource), false);

    const originFinding = { detector: "bytecode-origin", title: "ORIGIN (tx.origin) is used" };
    assert.equal(
      sourceCorroboratesPresence(originFinding, "require(msg.sender == tx.origin, \"eoa\");"),
      true,
    );

    const timestampFinding = { detector: "bytecode-timestamp", title: "TIMESTAMP is read" };
    assert.equal(
      sourceCorroboratesPresence(timestampFinding, "require(block.timestamp >= unlockTime);"),
      true,
    );

    const create2Finding = { detector: "bytecode-create2", title: "CREATE2 is present" };
    assert.equal(
      sourceCorroboratesPresence(create2Finding, "Token t = new Token{salt: salt}(arg);"),
      true,
    );
    assert.equal(
      sourceCorroboratesPresence(create2Finding, "assembly { let a := create2(0, ptr, len, s) }"),
      true,
    );

    const callShapeFinding = { detector: "bytecode-reentrancy-shape", title: "Both CALL and SSTORE are present" };
    assert.equal(
      sourceCorroboratesPresence(callShapeFinding, "(bool ok, ) = target.call{value: amount}(\"\");"),
      true,
    );

    // A non-presence finding is never "corroborated" by this path.
    assert.equal(
      sourceCorroboratesPresence({ detector: "reentrancy", title: "Reentrancy" }, delegatecallSource),
      false,
    );
    // No source (or an empty one) corroborates nothing.
    assert.equal(sourceCorroboratesPresence(presenceDelegatecall, null), false);
    assert.equal(sourceCorroboratesPresence(presenceDelegatecall, "  "), false);
  });
});
