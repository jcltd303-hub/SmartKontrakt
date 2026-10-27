import test from "node:test";
import assert from "node:assert/strict";

import {
  ECONOMIC_MAX_CHARS,
  ECONOMIC_SUMMARY_ABSENT,
  NARRATIVE_MAX_CHARS,
  ReviewCodeError,
  ReviewReplyError,
  TEST_CODE_MAX_CHARS,
  coerceModelText,
  modelValueKind,
  parseNarrativeReply,
  parseTestCodeReply,
} from "./ai-review.server.ts";
import { parseProposalReply } from "./deep-agent.server.ts";

/**
 * The LLM output contract (2026-10-27).
 *
 * These pin the places where a model's reply used to become a *lie* rather
 * than an error:
 *
 *  - `record.threatModelReport as string` passed the truthiness gate for an
 *    OBJECT, so `[object Object]` reached the stored narrative, the UI, and the
 *    next call's prompt. A cast is not a check.
 *  - nothing bounded the prose, and the narrative is interpolated into the
 *    code call's prompt — unbounded model output was unbounded prompt growth,
 *    the failure the two-call split was built to fix.
 *  - a missing economic summary was reported as "Completed OpenRouter threat
 *    review." — the analyzer claiming a review the model did not write.
 *  - a code reply could be over-long or pragma-less and still reach the Foundry
 *    backend, spending a run to discover it would not compile.
 */

const CODE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test} from "forge-std/Test.sol";
contract PoC is Test {
    function test_exploit() public { assertTrue(true); }
}`;

test("an object where prose belongs is recovered as text, never as [object Object]", () => {
  const reply = JSON.stringify({ threatModelReport: { executive: "the wallet is owned", risk: "high" } });
  const parsed = parseNarrativeReply(reply, "stop");
  assert.equal(typeof parsed.threatModelReport, "string");
  assert.match(parsed.threatModelReport, /the wallet is owned/);
  assert.doesNotMatch(parsed.threatModelReport, /\[object Object\]/);
});

test("an array of paragraphs is joined in order", () => {
  const reply = JSON.stringify({ threatModelReport: ["First paragraph.", "Second paragraph."] });
  assert.equal(parseNarrativeReply(reply, "stop").threatModelReport, "First paragraph.\nSecond paragraph.");
});

test("a number where prose belongs is rejected, and the error names the TYPE", () => {
  assert.throws(
    () => parseNarrativeReply(JSON.stringify({ threatModelReport: 42 }), "stop"),
    (err: unknown) => {
      assert.ok(err instanceof ReviewReplyError);
      assert.match(err.message, /types: threatModelReport=number/);
      assert.match(err.message, /missing threatModelReport/);
      assert.equal(err.receivedTypes, "threatModelReport=number");
      return true;
    },
  );
});

test("an empty-string narrative is rejected rather than stored as blank", () => {
  assert.throws(
    () => parseNarrativeReply(JSON.stringify({ threatModelReport: "   " }), "stop"),
    (err: unknown) => err instanceof ReviewReplyError,
  );
});

test("an over-long narrative is truncated with a visible marker, not silently cut", () => {
  const huge = "x".repeat(NARRATIVE_MAX_CHARS + 5_000);
  const parsed = parseNarrativeReply(JSON.stringify({ threatModelReport: huge }), "stop");
  assert.ok(parsed.threatModelReport.length < huge.length);
  assert.match(parsed.threatModelReport, /truncated at 24000 characters/);
  assert.match(parsed.threatModelReport, new RegExp(`${NARRATIVE_MAX_CHARS + 5000} characters`));
});

test("an over-long economic summary is bounded too", () => {
  const parsed = parseNarrativeReply(
    JSON.stringify({ threatModelReport: "tm", economicRiskSummary: "y".repeat(ECONOMIC_MAX_CHARS + 100) }),
    "stop",
  );
  assert.match(parsed.economicRiskSummary, /truncated at 4000 characters/);
});

test("a missing economic summary is stated, not claimed as completed", () => {
  const parsed = parseNarrativeReply(JSON.stringify({ threatModelReport: "tm" }), "stop");
  assert.equal(parsed.economicRiskSummary, ECONOMIC_SUMMARY_ABSENT);
  assert.doesNotMatch(parsed.economicRiskSummary, /Completed/);
});

test("modelValueKind distinguishes the shapes a model actually returns", () => {
  assert.equal(modelValueKind(undefined), "missing");
  assert.equal(modelValueKind(null), "null");
  assert.equal(modelValueKind("s"), "string");
  assert.equal(modelValueKind(1), "number");
  assert.equal(modelValueKind(["a", 1]), "array of string/number (length 2)");
  assert.equal(modelValueKind({ a: 1 }), "object");
});

test("coerceModelText rejects the non-text kinds and keeps the text ones", () => {
  assert.equal(coerceModelText(true, 100), null);
  assert.equal(coerceModelText(null, 100), null);
  assert.equal(coerceModelText([], 100), null);
  assert.equal(coerceModelText("  hi  ", 100), "hi");
});

test("test code over the length bound is REJECTED, not truncated", () => {
  const long = `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\ncontract PoC is Test {\n    function test_x() public {}\n}\n// ${"z".repeat(TEST_CODE_MAX_CHARS)}`;
  assert.throws(
    () => parseTestCodeReply("```solidity\n" + long + "\n```", "stop"),
    (err: unknown) => {
      assert.ok(err instanceof ReviewCodeError);
      assert.match(err.message, /over the 40000-character limit/);
      assert.match(err.correctiveInstruction(), /more compact test|exactly one ```solidity/);
      return true;
    },
  );
});

test("test code with no pragma is rejected so a compile failure is not discovered on a backend run", () => {
  const noPragma = "contract PoC is Test {\n    function test_x() public {}\n}";
  assert.throws(
    () => parseTestCodeReply("```solidity\n" + noPragma + "\n```", "stop"),
    (err: unknown) => {
      assert.ok(err instanceof ReviewCodeError);
      assert.match(err.message, /no pragma solidity directive/);
      return true;
    },
  );
});

test("a complete, bounded, pragma-bearing test still passes untouched", () => {
  assert.equal(parseTestCodeReply("```solidity\n" + CODE + "\n```", "stop"), CODE);
});

// ------------------------------------------------------------------
// The Deep Agent's proposal reply — same contract, different artifact
// ------------------------------------------------------------------

test("a proposal reply whose hypotheses field is a STRING yields no hypotheses instead of crashing", () => {
  // The inline version did `(parsed.hypotheses ?? []).filter(...)`, and a
  // string has no .filter — a schema miss killed the whole search round.
  const out = parseProposalReply({ hypotheses: "none found" });
  assert.deepEqual(out.hypotheses, []);
  assert.equal(out.stopReason, "no_new_hypotheses");
});

test("a proposal reply that is not an object at all is handled", () => {
  assert.deepEqual(parseProposalReply(["nope"]).hypotheses, []);
  assert.deepEqual(parseProposalReply(null).hypotheses, []);
  assert.deepEqual(parseProposalReply("prose").hypotheses, []);
});

test("a hypothesis without a real PoC is dropped, and a good one survives with defaults filled", () => {
  const out = parseProposalReply({
    hypotheses: [
      { title: "no poc", foundryTestCode: "contract Helper {}" },
      { title: "  real one  ", foundryTestCode: "contract PoC is Test {}", severity: "not-a-severity" },
    ],
  });
  assert.equal(out.hypotheses.length, 1);
  assert.equal(out.hypotheses[0]!.title, "real one");
  assert.equal(out.hypotheses[0]!.severity, "medium", "an unknown severity falls back to medium");
  assert.equal(out.hypotheses[0]!.detector, "deep-agent");
  assert.equal(out.stopReason, null);
});

test("over-long generated code is dropped rather than handed to the compiler", () => {
  const out = parseProposalReply({
    hypotheses: [{ title: "huge", foundryTestCode: `contract PoC is Test { /* ${"z".repeat(TEST_CODE_MAX_CHARS)} */ }` }],
  });
  assert.deepEqual(out.hypotheses, []);
});

test("at most two hypotheses per round survive, in order", () => {
  const out = parseProposalReply({
    hypotheses: [1, 2, 3, 4].map((n) => ({ title: `h${n}`, foundryTestCode: "contract PoC is Test {}" })),
  });
  assert.deepEqual(out.hypotheses.map((h) => h.title), ["h1", "h2"]);
});
