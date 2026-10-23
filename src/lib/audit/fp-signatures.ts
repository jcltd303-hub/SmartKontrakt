// src/lib/audit/fp-signatures.ts
//
// FP signature layer (G7): candidate false-positive patterns derived
// from the auditor's own dispositions, decided by a human, and used
// for ANNOTATION ONLY.
//
// Doctrine (hard lines, enforced by construction and by the negative
// invariant test in fp-signatures.test.ts): this layer never
// suppresses a finding, never changes a severity, never feeds
// pocAuditEligibility, and never writes a disposition. It does exactly
// three things:
//   1. derive CANDIDATE signatures from findings a human disposed as
//      'false_positive' (migration 0015 rows are the only input);
//   2. carry the human's confirm/dismiss decision per signature
//      (migration 0017; persistence in fp-signatures.server.ts);
//   3. annotate a finding that matches a CONFIRMED signature with a
//      visible "matches confirmed FP pattern" note at read time, so
//      the next triage pass over the same shape is faster.
// Unconfirmed (candidate) and dismissed signatures annotate nothing.
//
// ---------------------------------------------------------------------
// Signature shape — and why each field discriminates.
//
// The findings columns are the only evidence a disposed finding
// carries (0002): detector, title, location_fn, snippet, severity,
// confidence, swc. The signature is:
//
//   { detector, titlePattern, locationFn, snippetClass }
//
// - detector: the family. Necessary but NOT sufficient — a signature
//   that is just a detector id would annotate every finding that
//   detector ever emits, real ones included, so it never appears
//   alone: the three fields below always ride with it.
// - titlePattern: the detector's title TEMPLATE, recovered from the
//   stored title by normalization (fpTitlePattern). detect.ts builds
//   titles by interpolating the flagged function's name ("${fn.name}
//   sends tokens with no access check", "External call inside a loop
//   in ${fn.name}") and, for other families, static strings
//   ("Read-only reentrancy on ${varName}()", "SELFDESTRUCT is
//   reachable in the bytecode"). Masking the finding's own locationFn
//   and any hex address recovers the shared template; families whose
//   titles interpolate a contract or modifier name keep that name
//   literal, so their groups split per name rather than merging —
//   derivation is deliberately conservative (split over merge),
//   because a candidate only forms when the SAME literal shape recurs,
//   and a human confirms before anything annotates. (There is no
//   per-finding contract-name column to mask with; the scan-level name
//   is display-derived under the label rule, not a sound key.)
// - locationFn: the flagged function, pinned when the evidence rows
//   carry a real one. An FP shape is usually site-specific ("the
//   reentrancy flag inside claim(), whose guard the detector cannot
//   see"), and location_fn is the column that names the site.
//   Bytecode findings carry the placeholder 'runtime' there (every
//   bytecode finding does), so 'runtime'/absent normalizes to null =
//   "any function": pinning the placeholder would add no
//   discrimination and would wrongly exclude a source-shaped twin.
// - snippetClass: the SHAPE of the recorded evidence — 'disassembly'
//   (a bytecode.ts snippetFor window: offset + opcode lines),
//   'source' (source text), or 'empty'. This is the axis the FP fixes
//   kept turning on: the same detector + title is an FP when its only
//   evidence is opcode presence and a real finding when the snippet
//   shows a concrete call site. A signature derived from
//   disassembly-evidence FPs must not annotate a source-evidenced
//   finding of the same title, and vice versa.
//
// Deliberately NOT in the signature: severity and confidence (they
// are re-scored by calibration and analyzer baselines — the archive's
// stored severities predate the demotions, and the feed already
// re-derives currency at read time; pinning them would rot the
// signature against the very rows it should match) and swc (a coarser
// restatement of detector — several detectors share one SWC id — so
// it adds no discrimination beyond detector itself).
// ---------------------------------------------------------------------

import type { Finding } from "./types.ts";

/** The shape class of a finding's recorded evidence (its snippet). */
export type FpSnippetClass = "disassembly" | "source" | "empty";

/** The human's decision state for one signature. 'candidate' is the
 *  derived-but-undecided state; only 'confirmed' annotates. */
export type FpSignatureStatus = "candidate" | "confirmed" | "dismissed";

/** The discriminating payload of one FP signature (see header). */
export type FpSignaturePayload = {
  detector: string;
  titlePattern: string;
  locationFn: string | null;
  snippetClass: FpSnippetClass | null;
};

/** One fp_signatures row, as the UI and the read paths consume it:
 *  the payload, the human's decision, and the evidence snapshot the
 *  derivation last computed for it. */
export type FpSignature = FpSignaturePayload & {
  key: string;
  status: FpSignatureStatus;
  evidenceCount: number;
  scanCount: number;
  sampleFindingIds: string[];
  sampleTitles: string[];
  createdAt: string;
  updatedAt: string;
  decidedAt: string | null;
};

/** The annotation a confirmed match earns a finding. Carried on the
 *  Finding record as `fpMatch` (types.ts), attached at read time in
 *  persist.server.ts — the pocEvidence (G8) pattern. */
export type FpMatch = {
  signatureKey: string;
  detector: string;
  titlePattern: string;
};

export function isFpSignatureStatus(value: unknown): value is FpSignatureStatus {
  return value === "candidate" || value === "confirmed" || value === "dismissed";
}

/** The decisions a human may record. 'candidate' is derivation's
 *  state, never a decision. */
export function isFpSignatureDecision(value: unknown): value is "confirmed" | "dismissed" {
  return value === "confirmed" || value === "dismissed";
}

// A disassembly window (snippetFor in bytecode.ts) looks like
// "  00a3  DELEGATECALL" lines — the same shape adjudication.ts's
// DISASSEMBLY_LINE_RE recognizes. Kept as a local copy (adjudication
// does not export its regex); the snippetFor contract test in
// bytecode.test.ts and the class test here pin the same example.
const DISASSEMBLY_LINE_RE = /^\s*>?\s*[0-9a-f]{4}\s{2}[A-Z][A-Z0-9]*(\s|$)/m;

/** Classify a finding's snippet into its evidence shape. */
export function fpSnippetClass(snippet: string | null | undefined): FpSnippetClass {
  if (!snippet || !snippet.trim()) return "empty";
  return DISASSEMBLY_LINE_RE.test(snippet) ? "disassembly" : "source";
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Normalize a stored finding title to the detector's title template:
 * lowercase, collapse whitespace, mask hex addresses/hashes (they vary
 * per contract), and mask whole-token occurrences of the finding's
 * own function name (the dominant detect.ts interpolation — the name
 * is already carried separately as locationFn). Bare numbers stay:
 * some templates carry meaningful ones ("older than 0.8.0").
 * Derivation and matching both run titles through this exact function,
 * with the finding's own locationFn, so the comparison is symmetric.
 */
export function fpTitlePattern(title: string, locationFn: string | null | undefined): string {
  let t = title.trim().toLowerCase().replace(/\s+/g, " ");
  t = t.replace(/0x[0-9a-f]{8,}/g, "0x…");
  const fn = locationFn?.trim().toLowerCase();
  if (fn && fn !== "runtime" && fn.length >= 2) {
    t = t.replace(new RegExp(`(?<![a-z0-9_$])${escapeRegExp(fn)}(?![a-z0-9_$])`, "g"), "*");
  }
  return t;
}

/** The location a signature pins: the finding's real function name, or
 *  null for bytecode-placeholder/absent values (see header). */
function pinnedLocationFn(locationFn: string | null | undefined): string | null {
  const fn = locationFn?.trim();
  return fn && fn !== "runtime" ? fn : null;
}

/** The signature payload one finding's shape produces — the unit
 *  derivation groups by and matching compares against. */
export function fpSignaturePayloadForFinding(finding: {
  detector: string;
  title: string;
  locationFn?: string | null;
  snippet?: string | null;
}): FpSignaturePayload {
  return {
    detector: finding.detector,
    titlePattern: fpTitlePattern(finding.title, finding.locationFn),
    locationFn: pinnedLocationFn(finding.locationFn),
    snippetClass: fpSnippetClass(finding.snippet),
  };
}

/** Canonical identity of a payload: two signatures are the same
 *  pattern iff their keys are equal. This key is the fp_signatures
 *  primary key, so a dismissed key can be recognized (and never
 *  re-proposed) forever. */
export function fpSignatureKey(payload: FpSignaturePayload): string {
  return JSON.stringify([payload.detector, payload.titlePattern, payload.locationFn, payload.snippetClass]);
}

// ---------------------------------------------------------------------
// Derivation. Pure: rows in (one per false_positive-disposed finding),
// candidates out. A candidate requires agreement across at least
// MIN_FP_SIGNATURE_SCANS distinct scans — a single FP is an anecdote
// (one auditor, one contract, possibly a one-off judgment); two scans
// is the smallest evidence that the shape RECURS, which is the entire
// premise of a pattern layer. Note "scans", not "contracts": Jer's
// archive re-scans the same address repeatedly, and re-triaging the
// same FP on every re-scan is exactly the pain this layer exists to
// remove — the samples carry the scan ids so the human confirming a
// candidate can see whether its evidence is one address re-scanned or
// many contracts.
// ---------------------------------------------------------------------

export const MIN_FP_SIGNATURE_SCANS = 2;

const MAX_SAMPLE_FINDINGS = 5;
const MAX_SAMPLE_TITLES = 3;
const MAX_SAMPLE_SCANS = 10;

/** One false_positive-disposed finding, reduced to derivation's inputs. */
export type FpEvidenceRow = {
  findingId: string;
  scanId: string;
  detector: string;
  title: string;
  locationFn: string | null;
  snippet: string;
};

export type FpSignatureCandidate = {
  key: string;
  payload: FpSignaturePayload;
  evidenceCount: number;
  scanCount: number;
  scanIds: string[];
  sampleFindingIds: string[];
  sampleTitles: string[];
};

export function deriveFpSignatureCandidates(
  rows: readonly FpEvidenceRow[],
  opts?: { minScans?: number },
): FpSignatureCandidate[] {
  const minScans = opts?.minScans ?? MIN_FP_SIGNATURE_SCANS;
  const groups = new Map<string, { payload: FpSignaturePayload; rows: FpEvidenceRow[] }>();
  for (const row of rows) {
    const payload = fpSignaturePayloadForFinding(row);
    const key = fpSignatureKey(payload);
    const group = groups.get(key);
    if (group) group.rows.push(row);
    else groups.set(key, { payload, rows: [row] });
  }
  const out: FpSignatureCandidate[] = [];
  for (const [key, group] of groups) {
    const scanIds = [...new Set(group.rows.map((r) => r.scanId))].sort();
    if (scanIds.length < minScans) continue;
    const sampleTitles: string[] = [];
    for (const row of group.rows) {
      if (!sampleTitles.includes(row.title) && sampleTitles.length < MAX_SAMPLE_TITLES) {
        sampleTitles.push(row.title);
      }
    }
    out.push({
      key,
      payload: group.payload,
      evidenceCount: group.rows.length,
      scanCount: scanIds.length,
      scanIds: scanIds.slice(0, MAX_SAMPLE_SCANS),
      sampleFindingIds: group.rows
        .map((r) => r.findingId)
        .sort()
        .slice(0, MAX_SAMPLE_FINDINGS),
      sampleTitles,
    });
  }
  // Strongest evidence first; key order breaks ties deterministically.
  out.sort((a, b) => b.evidenceCount - a.evidenceCount || b.scanCount - a.scanCount || (a.key < b.key ? -1 : 1));
  return out;
}

// ---------------------------------------------------------------------
// Matching + annotation. Matching uses exactly the stored signature
// semantics: detector equal, title pattern equal (the candidate
// finding's title normalized with ITS OWN locationFn), a pinned
// locationFn equal, a pinned snippetClass equal. Null pins are
// wildcards. Only CONFIRMED signatures are ever passed in by the read
// paths — fpMatchForFinding additionally takes the full row list plus
// a status filter helper so tests can pin that candidates and
// dismissed rows annotate nothing.
// ---------------------------------------------------------------------

export function findingMatchesFpSignature(
  finding: { detector: string; title: string; locationFn?: string | null; snippet?: string | null },
  signature: FpSignaturePayload,
): boolean {
  if (finding.detector !== signature.detector) return false;
  if (fpTitlePattern(finding.title, finding.locationFn) !== signature.titlePattern) return false;
  if (signature.locationFn !== null && pinnedLocationFn(finding.locationFn) !== signature.locationFn) {
    return false;
  }
  if (signature.snippetClass !== null && fpSnippetClass(finding.snippet) !== signature.snippetClass) {
    return false;
  }
  return true;
}

/** The subset of signature rows allowed to annotate: confirmed only. */
export function confirmedFpSignatures<T extends { status: FpSignatureStatus }>(
  rows: readonly T[],
): T[] {
  return rows.filter((r) => r.status === "confirmed");
}

/**
 * The annotation for one finding against a list of CONFIRMED
 * signatures (pass confirmedFpSignatures(...) output), or null when
 * nothing confirmed matches. First match wins; the list order is the
 * caller's (read paths pass evidence-strongest first).
 */
export function fpMatchForFinding(
  finding: { detector: string; title: string; locationFn?: string | null; snippet?: string | null },
  confirmed: readonly FpSignature[],
): FpMatch | null {
  for (const sig of confirmed) {
    if (sig.status !== "confirmed") continue;
    if (findingMatchesFpSignature(finding, sig)) {
      return { signatureKey: sig.key, detector: sig.detector, titlePattern: sig.titlePattern };
    }
  }
  return null;
}

/** The Finding shape this module reads — exported for the read paths
 *  so the field list lives in one place. */
export type FpFindingShape = Pick<Finding, "detector" | "title" | "locationFn" | "snippet">;
