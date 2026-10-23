// src/lib/audit/fp-signatures.test.ts
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  confirmedFpSignatures,
  deriveFpSignatureCandidates,
  findingMatchesFpSignature,
  fpMatchForFinding,
  fpSignatureKey,
  fpSignaturePayloadForFinding,
  fpSnippetClass,
  fpTitlePattern,
  MIN_FP_SIGNATURE_SCANS,
  type FpEvidenceRow,
  type FpSignature,
} from "./fp-signatures.ts";
import { hasVulnCorroboration, pocAuditEligibility, suggestDispositionForVerdict } from "./adjudication.ts";

// A source-shaped FP: the access-control detector flagging `harvest`,
// whose snippet shows ordinary source (the shape Jer's FPs take when a
// guard or role check sits outside the detector's view).
const SOURCE_SNIPPET = "function harvest() public {\n  token.transfer(owner, token.balanceOf(address(this)));\n}";
const sourceRow = (scanId: string, ord: number, over: Partial<FpEvidenceRow> = {}): FpEvidenceRow => ({
  findingId: `${scanId}:${ord}`,
  scanId,
  detector: "access-control",
  title: "harvest sends tokens with no access check",
  locationFn: "harvest",
  snippet: SOURCE_SNIPPET,
  ...over,
});

// A bytecode-presence FP: disassembly-window snippet, 'runtime' fn.
const DISASM_SNIPPET = "> 0000  DELEGATECALL\n  0002  ISZERO\n  0003  PUSH1 0x00";
const presenceRow = (scanId: string, ord: number, over: Partial<FpEvidenceRow> = {}): FpEvidenceRow => ({
  findingId: `${scanId}:${ord}`,
  scanId,
  detector: "bytecode-delegatecall",
  title: "DELEGATECALL executes foreign code in this contract's storage context",
  locationFn: "runtime",
  snippet: DISASM_SNIPPET,
  ...over,
});

const asSignature = (row: FpEvidenceRow, status: FpSignature["status"]): FpSignature => {
  const payload = fpSignaturePayloadForFinding(row);
  return {
    ...payload,
    key: fpSignatureKey(payload),
    status,
    evidenceCount: 2,
    scanCount: 2,
    sampleFindingIds: [row.findingId],
    sampleTitles: [row.title],
    createdAt: "2026-10-23T00:00:00Z",
    updatedAt: "2026-10-23T00:00:00Z",
    decidedAt: status === "candidate" ? null : "2026-10-23T00:00:00Z",
  };
};

describe("fpTitlePattern — recovering the detector's title template", () => {
  it("masks the finding's own function name (the detect.ts interpolation)", () => {
    assert.equal(
      fpTitlePattern("harvest sends tokens with no access check", "harvest"),
      "* sends tokens with no access check",
    );
    assert.equal(fpTitlePattern("External call inside a loop in claim", "claim"), "external call inside a loop in *");
  });

  it("does not mask the name inside a longer word, and keeps meaningful numbers", () => {
    assert.equal(fpTitlePattern("claims are processed by the vault", "claim"), "claims are processed by the vault");
    assert.equal(fpTitlePattern("Compiler is older than 0.8.0", null), "compiler is older than 0.8.0");
  });

  it("masks hex addresses and normalizes case/whitespace", () => {
    assert.equal(
      fpTitlePattern("  Token   0x1234567890abcdef1234567890abcdef12345678  drained ", null),
      "token 0x… drained",
    );
  });
});

describe("fpSnippetClass — the evidence-shape axis", () => {
  it("classifies disassembly windows, source text, and absence", () => {
    assert.equal(fpSnippetClass(DISASM_SNIPPET), "disassembly");
    assert.equal(fpSnippetClass(SOURCE_SNIPPET), "source");
    assert.equal(fpSnippetClass(""), "empty");
    assert.equal(fpSnippetClass("   \n "), "empty");
    assert.equal(fpSnippetClass(null), "empty");
  });
});

describe("deriveFpSignatureCandidates", () => {
  it("the recurrence threshold is pinned at two distinct scans", () => {
    assert.equal(MIN_FP_SIGNATURE_SCANS, 2);
  });

  it("the same shape across two scans derives one candidate, with pins and samples", () => {
    const candidates = deriveFpSignatureCandidates([sourceRow("scan-1", 3), sourceRow("scan-2", 1)]);
    assert.equal(candidates.length, 1);
    const [c] = candidates;
    assert.equal(c.payload.detector, "access-control");
    assert.equal(c.payload.titlePattern, "* sends tokens with no access check");
    assert.equal(c.payload.locationFn, "harvest");
    assert.equal(c.payload.snippetClass, "source");
    assert.equal(c.evidenceCount, 2);
    assert.equal(c.scanCount, 2);
    assert.deepEqual(c.scanIds, ["scan-1", "scan-2"]);
    assert.deepEqual(c.sampleFindingIds, ["scan-1:3", "scan-2:1"]);
    assert.deepEqual(c.sampleTitles, ["harvest sends tokens with no access check"]);
    assert.equal(c.key, fpSignatureKey(c.payload));
  });

  it("two FPs in ONE scan are an anecdote, not a candidate", () => {
    assert.deepEqual(deriveFpSignatureCandidates([sourceRow("scan-1", 3), sourceRow("scan-1", 4)]), []);
    assert.deepEqual(deriveFpSignatureCandidates([sourceRow("scan-1", 3)]), []);
  });

  it("a differing function, title, or evidence shape derives a separate candidate", () => {
    const rows = [
      sourceRow("scan-1", 3),
      sourceRow("scan-2", 1),
      // same detector + title template, different function
      sourceRow("scan-1", 5, { title: "claim sends tokens with no access check", locationFn: "claim" }),
      sourceRow("scan-3", 0, { title: "claim sends tokens with no access check", locationFn: "claim" }),
      // same detector + title, disassembly evidence instead of source
      presenceRow("scan-1", 7),
      presenceRow("scan-4", 2),
    ];
    const candidates = deriveFpSignatureCandidates(rows);
    assert.equal(candidates.length, 3);
    const byFn = new Map(candidates.map((c) => [c.payload.locationFn, c]));
    assert.equal(byFn.get("harvest")?.payload.snippetClass, "source");
    assert.equal(byFn.get("claim")?.payload.snippetClass, "source");
    // The bytecode rows pin no function ('runtime' is a placeholder)
    // and pin the disassembly class.
    assert.equal(byFn.get(null)?.payload.detector, "bytecode-delegatecall");
    assert.equal(byFn.get(null)?.payload.snippetClass, "disassembly");
  });

  it("samples are capped and the strongest evidence sorts first", () => {
    const many = Array.from({ length: 7 }, (_, i) => sourceRow(`scan-${(i % 3) + 1}`, i));
    const pair = [presenceRow("scan-8", 0), presenceRow("scan-9", 0)];
    const candidates = deriveFpSignatureCandidates([...pair, ...many]);
    assert.equal(candidates.length, 2);
    assert.equal(candidates[0].evidenceCount, 7);
    assert.equal(candidates[0].scanCount, 3);
    assert.equal(candidates[0].sampleFindingIds.length, 5);
    assert.equal(candidates[1].evidenceCount, 2);
  });
});

describe("matching + annotation", () => {
  const confirmed = asSignature(sourceRow("scan-1", 3), "confirmed");

  it("a confirmed signature matches a fresh finding of the same shape", () => {
    const finding = {
      detector: "access-control",
      title: "harvest sends tokens with no access check",
      locationFn: "harvest",
      snippet: SOURCE_SNIPPET,
    };
    assert.equal(findingMatchesFpSignature(finding, confirmed), true);
    const match = fpMatchForFinding(finding, [confirmed]);
    assert.equal(match?.signatureKey, confirmed.key);
    assert.equal(match?.detector, "access-control");
  });

  it("the pinned function and the pinned evidence shape both discriminate", () => {
    const base = {
      detector: "access-control",
      title: "harvest sends tokens with no access check",
      locationFn: "harvest",
      snippet: SOURCE_SNIPPET,
    };
    assert.equal(findingMatchesFpSignature({ ...base, locationFn: "sweep" }, confirmed), false);
    assert.equal(findingMatchesFpSignature({ ...base, snippet: DISASM_SNIPPET }, confirmed), false);
    assert.equal(findingMatchesFpSignature({ ...base, detector: "reentrancy" }, confirmed), false);
    assert.equal(
      findingMatchesFpSignature({ ...base, title: "harvest sends tokens with no access check (proxy)" }, confirmed),
      false,
    );
  });

  it("candidate and dismissed signatures annotate nothing", () => {
    const finding = {
      detector: "access-control",
      title: "harvest sends tokens with no access check",
      locationFn: "harvest",
      snippet: SOURCE_SNIPPET,
    };
    const candidate = asSignature(sourceRow("scan-1", 3), "candidate");
    const dismissed = asSignature(sourceRow("scan-1", 3), "dismissed");
    assert.equal(fpMatchForFinding(finding, [candidate]), null);
    assert.equal(fpMatchForFinding(finding, [dismissed]), null);
    assert.deepEqual(confirmedFpSignatures([candidate, dismissed, confirmed]), [confirmed]);
    // Even a mixed list annotates only through the confirmed row.
    assert.equal(fpMatchForFinding(finding, [candidate, dismissed, confirmed])?.signatureKey, confirmed.key);
  });
});

describe("negative invariant — annotation is not evidence", () => {
  it("a confirmed match changes neither eligibility, corroboration, severity, nor suggestions", () => {
    // A presence-only critical that matches a confirmed FP pattern:
    // the FP layer's whole point is that this finding still goes
    // through the same gates as before — the note only tells the
    // human "you have judged this shape an FP before".
    const finding = {
      severity: "critical",
      detector: "bytecode-delegatecall",
      title: "DELEGATECALL executes foreign code in this contract's storage context",
      locationFn: "runtime",
      snippet: DISASM_SNIPPET,
    };
    const sig = asSignature(presenceRow("scan-1", 7), "confirmed");
    const match = fpMatchForFinding(finding, [sig]);
    assert.ok(match, "the shape must actually match for this test to mean anything");

    const annotated = { ...finding, fpMatch: match };
    assert.deepEqual(pocAuditEligibility(annotated, "critical"), pocAuditEligibility(finding, "critical"));
    assert.deepEqual(pocAuditEligibility(annotated, "critical"), {
      eligible: false,
      exclusion: "presence_only",
    });
    assert.equal(hasVulnCorroboration(annotated), hasVulnCorroboration(finding));
    assert.equal(annotated.severity, finding.severity);
    assert.equal(suggestDispositionForVerdict("failed"), suggestDispositionForVerdict("failed"));
    assert.equal(suggestDispositionForVerdict(null), "needs_more_info");
  });
});
