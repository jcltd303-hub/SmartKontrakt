// src/lib/audit/adjudication.ts
//
// Pure adjudication logic shared by the workbench findings tab and the
// PoC Audits page: the disposition vocabulary, the verdict → suggestion
// map, the idempotency planner (what the one-action chain may skip), the
// PoC candidate preparation, the PoC Audits feed dedupe, and the AI-review
// excerpt picker.
//
// Everything here is a pure function of its inputs — no database, no
// network, no server imports — so the skip/suggestion/dedupe behaviour is
// unit-testable across its whole input matrix (adjudication.test.ts).
// The chain that ACTS on these decisions lives in adjudicate-chain.ts;
// persistence lives in dispositions.server.ts. A disposition itself is
// only ever written by a human tap (setFindingDispositionFn) — this
// module computes SUGGESTIONS, never verdicts of record.

import { wrapPocSnippetWithReason } from "./poc-wrap.ts";
import { selectPocFallbacks } from "./poc-fallbacks.ts";
import type { AiSecurityReview } from "./ai-review.server.ts";
import type { Finding } from "./types.ts";

/** The auditor's verdict on one finding. Written only by a human. */
export type AuditorDisposition = "confirmed" | "false_positive" | "needs_more_info";

export const AUDITOR_DISPOSITIONS: readonly AuditorDisposition[] = [
  "confirmed",
  "false_positive",
  "needs_more_info",
] as const;

export function isAuditorDisposition(value: unknown): value is AuditorDisposition {
  return value === "confirmed" || value === "false_positive" || value === "needs_more_info";
}

/** One persisted disposition row, as the UI consumes it. */
export type FindingDisposition = {
  findingId: string;
  disposition: AuditorDisposition;
  note: string | null;
  updatedAt: string;
};

/** Terminal verdict of one PoC execution (or of a reused stored run).
 *  "no_tests" (the PoC contained no executable test function, so the
 *  harness ran 0 tests), "skipped" (the value guard found nothing
 *  at stake) and "unadapted" (the PoC was a fallback template whose
 *  required TODO constants were never filled, so it would abort on
 *  its own precondition) are first-class terminal outcomes, distinct
 *  from "error" — none is a failure and none is evidence about the
 *  bug. */
export type PocVerdict = "passed" | "failed" | "error" | "no_tests" | "skipped" | "unadapted";

/**
 * Verdict → SUGGESTED disposition. The mapping is deliberately literal:
 * a reproduced exploit suggests the finding is real; a clean
 * not-reproduced run suggests a false positive; anything that is not a
 * verdict at all (infra error, timeout, backend down, no run) suggests
 * "needs more info" — an error must never masquerade as evidence either
 * way. "no_tests", "skipped" and "unadapted" land in the same place for
 * the same reason: generation produced no executable tests, the target
 * holds no value at stake, or the harness was a template scaffold whose
 * TODO constants were never filled — none is evidence about the bug.
 * The human still has to tap to make it of record.
 */
export function suggestDispositionForVerdict(verdict: PocVerdict | null): AuditorDisposition {
  if (verdict === "passed") return "confirmed";
  if (verdict === "failed") return "false_positive";
  return "needs_more_info";
}

/** A stored PoC run, reduced to what the planner needs. */
export type PocRunDigestRef = {
  digest: string;
  status: string;
};

export type AdjudicationPlan = {
  /** A disposition already exists and no redo was requested: the chain
   *  does nothing at all and reports the finding as already adjudicated. */
  alreadyAdjudicated: boolean;
  /** An AI review already exists for the scan: reuse it, never spend a
   *  second OpenRouter call on the same scan. */
  reuseReview: boolean;
  /** A terminal run already exists for the exact PoC that would run:
   *  reuse its verdict instead of re-executing on the backend. */
  reuseRun: PocRunDigestRef | null;
};

/**
 * The idempotency planner for the adjudication chain. Pure decision
 * function over the finding's current state:
 *
 * - hasDisposition && !force → already adjudicated, skip everything.
 * - hasReview → the AI step is a reuse, not a new call.
 * - a stored run whose digest equals the candidate PoC's digest → the
 *   run step is a reuse; its stored status becomes the verdict.
 *
 * `force` is the per-finding "redo" affordance: it overrides every skip
 * (including the disposition skip — redo re-runs the chain and lands on a
 * fresh suggestion; the stored disposition itself is left untouched
 * until the human accepts a new one).
 */
export function planAdjudication(input: {
  hasDisposition: boolean;
  hasReview: boolean;
  candidateDigest: string | null;
  existingRuns: readonly PocRunDigestRef[];
  force?: boolean;
}): AdjudicationPlan {
  if (input.hasDisposition && !input.force) {
    return { alreadyAdjudicated: true, reuseReview: true, reuseRun: null };
  }
  let reuseRun: PocRunDigestRef | null = null;
  if (!input.force && input.candidateDigest) {
    // Terminal outcomes for the exact PoC: the two verdicts, an error,
    // a no_tests (re-running the identical source would run the
    // identical zero tests), a skipped (same source, same guard) and
    // an unadapted (same source, same unfilled TODO constants).
    // A redo (force) is the explicit way past any of them.
    reuseRun =
      input.existingRuns.find(
        (r) =>
          r.digest === input.candidateDigest &&
          (r.status === "passed" ||
            r.status === "failed" ||
            r.status === "error" ||
            r.status === "no_tests" ||
            r.status === "skipped" ||
            r.status === "unadapted"),
      ) ?? null;
  }
  return {
    alreadyAdjudicated: false,
    reuseReview: input.hasReview,
    reuseRun,
  };
}

/**
 * The PoC the chain would run for a finding, prepared exactly the way the
 * workbench Run button prepares it: wrap the finding's exploit snippet
 * into a runnable Foundry test; when the snippet cannot be wrapped and is
 * not already a test, fall back to the best-matching library template for
 * the finding's detector class. Returns null when nothing runnable can
 * be produced (no snippet and no template) — the chain then ends at a
 * "needs more info" suggestion instead of inventing a run.
 */
export function prepareFindingPoc(
  finding: Pick<Finding, "exploitSolidity" | "severity" | "detector">,
): { source: string; testCode: string; note: string | null } | null {
  let source = finding.exploitSolidity ?? "";
  let outcome = wrapPocSnippetWithReason(source);
  if (!outcome.wrapped) {
    const isTest = /\bcontract\s+\w+\s+is\s+[^{]*\bTest\b/.test(source);
    const hasTestFn = /function\s+test_\w*\s*\(|function\s+testPoc\s*\(/.test(source);
    if (!isTest || !hasTestFn) {
      const fallbacks = selectPocFallbacks(
        [{ severity: finding.severity, detector: finding.detector }],
        1,
      );
      if (fallbacks.length > 0 && fallbacks[0]?.source) {
        source = fallbacks[0].source;
        outcome = wrapPocSnippetWithReason(source);
      }
    }
  }
  if (!source.trim()) return null;
  if (outcome.wrapped) {
    return { source, testCode: outcome.wrapped.testFile, note: outcome.wrapped.note ?? null };
  }
  // Unwrapped but a complete test already: runnable as-is. Anything else
  // (a bare attack contract the wrapper rejected, pseudocode) is not
  // executable — report it as unpreparable rather than shipping the
  // backend a guaranteed zero-test "run".
  const isTest = /\bcontract\s+\w+\s+is\s+[^{]*\bTest\b/.test(source);
  const hasTestFn = /function\s+test_\w*\s*\(|function\s+testPoc\s*\(/.test(source);
  if (isTest && hasTestFn) return { source, testCode: source, note: outcome.reason ?? null };
  return null;
}

/**
 * Identity of "the same finding" for the PoC Audits feed. Finding rows
 * are keyed `${scanId}:${ord}` (bulk-persist), and every RE-SCAN of an
 * address mints a fresh scan with fresh finding rows — Jer's archive
 * carries one address whose same finding title appears 18 times, once
 * per scan of that address (the doubled "initialize" rows in his PoC
 * Audits screenshot are two scans of the same proxy). The feed identity
 * is therefore exactly (target_address, detector, title) — chain is
 * deliberately NOT part of the key, so the same address re-scanned
 * under a different chain label ("ethereum" vs "1") still collapses.
 * Address-less (pasted-source) scans fall back to scan-scoped identity,
 * where duplicates can only come from the detector emitting the same
 * finding twice in one report. Nothing is deleted: the archive keeps
 * every scan's rows; only the feed collapses to latest-per-address.
 */
export function findingFeedIdentityKey(row: {
  scanId: string;
  detector: string;
  title: string;
  targetAddress?: string | null;
}): string {
  const title = row.title.trim().toLowerCase();
  const detector = row.detector.trim().toLowerCase();
  const address = row.targetAddress?.trim().toLowerCase() ?? "";
  if (address) return `addr:${address}:${detector}:${title}`;
  return `scan:${row.scanId}:${detector}:${title}`;
}

/**
 * One row per finding identity, first occurrence wins. ORDERING
 * CONTRACT: callers pass rows newest-scan-first (the feed query orders
 * by scan created_at DESC), so the surviving row is the LATEST scan's
 * copy — the one whose PoC state and disposition are current. Pure and
 * total: the input order is otherwise preserved exactly.
 */
export function dedupeRecentFindings<
  T extends {
    scanId: string;
    detector: string;
    title: string;
    targetAddress?: string | null;
  },
>(rows: readonly T[]): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const row of rows) {
    const key = findingFeedIdentityKey(row);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(row);
  }
  return out;
}

/**
 * "Actually critical" scope for the PoC Audits queues (Jer's rule,
 * applied at READ time because the archive's stored severities predate
 * the detector demotions): a finding is queue-eligible when it is
 * critical — highs only when the scope is explicitly widened — AND it
 * is not a bytecode-presence-only finding.
 *
 * The presence family (bytecode.ts): findings emitted purely because an
 * opcode EXISTS in the runtime — DELEGATECALL / CALLCODE / SELFDESTRUCT
 * and their presence siblings (ORIGIN used, TIMESTAMP read, CREATE2
 * present, CALL+SSTORE present). Their sole recorded evidence is opcode
 * presence, so a fork PoC against them proves nothing about THIS
 * contract. The exception — "unless the bytes clearly depict vuln" — is
 * hasVulnCorroboration below.
 */
export type PocAuditScope = "critical" | "critical_and_high";

export type PocAuditExclusion = "presence_only" | "below_scope";

const PRESENCE_DETECTORS: ReadonlySet<string> = new Set([
  "bytecode-delegatecall",
  "bytecode-callcode",
  "bytecode-selfdestruct",
]);

const PRESENCE_TITLE_RE =
  /executes foreign code in this contract's storage|is reachable in the bytecode|^ORIGIN \(tx\.origin\) is used$|^TIMESTAMP is read$|^CREATE2 is present$|^Both CALL and SSTORE are present$/;

export function isPresenceOnlyFinding(finding: { detector: string; title: string }): boolean {
  if (PRESENCE_DETECTORS.has(finding.detector)) return true;
  return PRESENCE_TITLE_RE.test(finding.title.trim());
}

// A disassembly window (snippetFor in bytecode.ts) looks like
// "  00a3  DELEGATECALL" lines — presence evidence, not a call site.
const DISASSEMBLY_LINE_RE = /^\s*>?\s*[0-9a-f]{4}\s{2}[A-Z][A-Z0-9]*(\s|$)/m;
// A source-level call site: an actual call expression in source text.
const SOURCE_CALLSITE_RE = /(delegatecall|callcode|selfdestruct|\.call)\s*[({]/;

/**
 * Corroboration that takes a presence-family finding OUT of the
 * presence-only class ("the bytes clearly depict vuln"):
 * - an explicit corroboration marker on the record, when one exists
 *   (preferred — the FP-patterns work may stamp one); or
 * - a source-level location: a real function name (bytecode findings
 *   carry locationFn "runtime") whose snippet is source text showing a
 *   concrete call site, not a disassembly window.
 */
export function hasVulnCorroboration(finding: {
  locationFn?: string | null;
  snippet?: string | null;
  corroborated?: unknown;
}): boolean {
  if (finding.corroborated === true) return true;
  if (typeof finding.corroborated === "string" && finding.corroborated.trim()) return true;
  const fn = finding.locationFn?.trim();
  const snippet = finding.snippet ?? "";
  if (!fn || fn === "runtime" || !snippet.trim()) return false;
  if (DISASSEMBLY_LINE_RE.test(snippet)) return false;
  return SOURCE_CALLSITE_RE.test(snippet);
}

export function pocAuditEligibility(
  finding: {
    severity: string;
    detector: string;
    title: string;
    locationFn?: string | null;
    snippet?: string | null;
    corroborated?: unknown;
  },
  scope: PocAuditScope,
): { eligible: boolean; exclusion: PocAuditExclusion | null } {
  // Presence is checked first, at every severity: an uncorroborated
  // presence-only "critical" is still not actually critical.
  if (isPresenceOnlyFinding(finding) && !hasVulnCorroboration(finding)) {
    return { eligible: false, exclusion: "presence_only" };
  }
  if (finding.severity === "critical") return { eligible: true, exclusion: null };
  if (scope === "critical_and_high" && finding.severity === "high") {
    return { eligible: true, exclusion: null };
  }
  return { eligible: false, exclusion: "below_scope" };
}

/**
 * Partition a feed into the queue-eligible rows and the two exclusion
 * buckets. `presenceOnlyExcluded.length` is the header's "N
 * presence-only excluded" count; the buckets plus `eligible` always sum
 * to the input length.
 */
export function partitionPocAuditFindings<
  T extends {
    severity: string;
    detector: string;
    title: string;
    locationFn?: string | null;
    snippet?: string | null;
    corroborated?: unknown;
  },
>(
  rows: readonly T[],
  scope: PocAuditScope,
): { eligible: T[]; presenceOnlyExcluded: T[]; belowScope: T[] } {
  const eligible: T[] = [];
  const presenceOnlyExcluded: T[] = [];
  const belowScope: T[] = [];
  for (const row of rows) {
    const verdict = pocAuditEligibility(row, scope);
    if (verdict.eligible) eligible.push(row);
    else if (verdict.exclusion === "presence_only") presenceOnlyExcluded.push(row);
    else belowScope.push(row);
  }
  return { eligible, presenceOnlyExcluded, belowScope };
}

/**
 * The part of a scan's AI review that actually discusses this finding,
 * or null when the review never mentions it. The review is scan-level
 * prose (threat model + economic summary); an excerpt is only claimed
 * "for this finding" when a paragraph names the finding's title or
 * detector — anything else would fabricate per-finding coverage the
 * review does not have.
 */
export function aiReviewExcerptForFinding(
  review: Pick<AiSecurityReview, "threatModelReport" | "economicRiskSummary"> | null | undefined,
  finding: Pick<Finding, "title" | "detector">,
  maxChars = 600,
): string | null {
  if (!review) return null;
  const needles = [finding.title.trim().toLowerCase(), finding.detector.trim().toLowerCase()].filter(
    (n) => n.length >= 4,
  );
  if (needles.length === 0) return null;
  const text = [review.threatModelReport, review.economicRiskSummary].filter(Boolean).join("\n\n");
  const paragraphs = text.split(/\n{2,}/).map((p) => p.trim()).filter(Boolean);
  for (const para of paragraphs) {
    const lower = para.toLowerCase();
    if (needles.some((n) => lower.includes(n))) {
      return para.length > maxChars ? `${para.slice(0, maxChars).trimEnd()}…` : para;
    }
  }
  return null;
}
