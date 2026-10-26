// src/lib/audit/poc-outcome.ts
//
// The PoC outcome vocabulary, shared by every surface that produces or
// consumes a run result: foundry-backend (runSmartPoc), the PoC Audits
// page (Run PoC / AUDIT ALL), the adjudication chain, and the counters
// that read stored rows back.
//
// The vocabulary distinguishes OUTCOME KINDS that used to be conflated
// into "error":
//
// - "passed" / "failed" — real verdicts: tests executed on the fork and
//   the assertions held / did not hold.
// - "error" — a REAL failure: compile error, backend unreachable, RPC /
//   fork failure, timeout. Something went wrong before a verdict.
// - "no_tests" — the harness had nothing to execute: the prepared PoC
//   contained no executable test function, so forge ran 0 tests. Not an
//   error (nothing failed) and not a verdict (nothing was tested) — a
//   generation gap.
// - "skipped" — a deliberate non-run: the pre-run value guard found the
//   target holds no value at stake. Not an error, not a verdict, and
//   not evidence about the bug either way.
// - "unadapted" — a deliberate non-run: the PoC is a fallback-library
//   template whose required TODO constants were never filled, so it
//   would abort on its own precondition before judging the target.
//   The pre-check below catches it BEFORE the backend; the TODO-abort
//   require messages reclassify runs that were executed anyway.
//
// findings.poc_status and finding_poc_runs.status are plain text
// columns (migrations 0004/0008 carry no CHECK constraint), so these
// kinds persist without a migration.
//
// Stored rows predate the vocabulary: tests=0 runs and value-guard
// skips were saved as "error". effectivePocStatus reclassifies those
// rows on READ (the same read-time rule the actually-critical scope
// uses for stale severities), so counters tell the truth about the
// existing archive without rewriting it.

import {
  POC_FALLBACK_TEMPLATES,
  POC_FALLBACK_TODO_REQUIREMENTS,
} from "./poc-fallbacks.ts";
import type { PocOrigin } from "./poc-evidence.ts";

/** The statuses a run can be SAVED under (findings.poc_status /
 *  finding_poc_runs.status). The transport-level "backend_unreachable"
 *  is deliberately not one of them — it saves as "error". */
export type SavedPocStatus = "passed" | "failed" | "error" | "no_tests" | "skipped" | "unadapted";

/** Forge's own "nothing ran" output shapes, plus the SmartPoC header's
 *  tests=0 marker. A run whose output carries any of these executed
 *  zero tests, whatever its transport status claims. */
const ZERO_TESTS_RE = /tests=0(?!\d)|no tests (match|found)|ran 0 tests|0 passed;\s*0 failed/i;

export function hasZeroTestEvidence(output: string | null | undefined): boolean {
  if (!output) return false;
  return ZERO_TESTS_RE.test(output);
}

/** The pre-run value guard's log prefix (runSmartPoc in
 *  foundry-backend.ts). A stored output carrying it was a deliberate
 *  skip, even when the row was saved as "error" in the old vocabulary. */
const SKIP_SENTINEL = "[SmartPoC] Skipped";

export function hasSkipSentinel(output: string | null | undefined): boolean {
  if (!output) return false;
  return output.includes(SKIP_SENTINEL);
}

/** The TODO-precondition abort messages of the fallback templates whose
 *  required constants ship zero (index.json `todo`). Each is the exact
 *  require string in the shipped template — poc-outcome.test.ts pins
 *  every entry against the template sources, so a template edit that
 *  rewords its abort fails the test instead of silently un-matching
 *  the archive's stored rows. A run whose output carries one of these
 *  aborted on the scaffold's own precondition: it never judged the
 *  target, whatever the transport status claims. */
export const TODO_ABORT_MARKERS: readonly string[] = [
  "set OWNER to the trusted victim account", // 09
  "set ROUTER / tokens / WHALE", // 16
  "set TOKEN_OUT / WHALE", // 16 (second entry point)
  "set ROUTER / tokens / VICTIM / WHALE", // 17
  "set MESSAGE_HASH to the target's signed message hash", // 18 + 19
  "set PRICE to the per-item price", // 22
  "set TOKEN to the ERC777 token address", // 03
  "set PRICE to one NFT's mint price", // 04
  "set AMOUNT + proof to a valid claim for the attacker", // 36
  "set WHALE to a governance-token holder on this fork", // 38
  "set WHALE to an asset holder on this fork", // 40
  "set POOL / ASSET", // 35
  "set TOKEN / VICTIM / SPENDER", // 37
];

/** The pre-check's own saved-output prefix (unadaptedTemplateOutput). */
export const UNADAPTED_SENTINEL = "[SmartPoC] Not run — unadapted fallback template";

export function hasUnadaptedEvidence(output: string | null | undefined): boolean {
  if (!output) return false;
  if (output.includes(UNADAPTED_SENTINEL)) return true;
  return TODO_ABORT_MARKERS.some((marker) => output.includes(marker));
}

/**
 * Inconclusive / un-reproduced signals in Foundry output.
 * Some PoC tests log that the interaction failed, re-entry was impossible,
 * or the scenario was inconclusive, but Forge reports [PASS] because
 * no revert/assertion failed inside the test function.
 * These hollow passes must be classified as failed (exploit not reproduced).
 */
export const INCONCLUSIVE_POC_RE =
  /\b(inconclusive|did not reproduce|attack contract interaction failed|exploit did not reproduce)\b/i;

export function hasInconclusiveEvidence(output: string | null | undefined): boolean {
  if (!output) return false;
  return INCONCLUSIVE_POC_RE.test(output);
}

/**
 * Map a FRESH run result to the status it is saved under. The run's own
 * status field is authoritative here — a value-guard skip arrives as
 * status "skipped", never embedded in an "error" — except for the
 * hollow-verdict guard: a "passed"/"failed" whose output evidences
 * zero executed tests is not a verdict and becomes "no_tests", and a
 * "passed" whose logs show the attack was inconclusive or failed to
 * interact becomes "failed".
 */
export function savedStatusFromRun(run: { status: string; logs?: string | null }): SavedPocStatus {
  const logs = run.logs ?? "";
  if (run.status === "skipped") return "skipped";
  if (run.status === "no_tests") return "no_tests";
  if (run.status === "unadapted") return "unadapted";
  // A run that aborted on a template's TODO precondition never judged
  // the target — it is an unadapted scaffold, not a failed verdict and
  // not an infra error. (Checked before the zero-test rule: a setUp
  // TODO abort can also evidence zero executed tests, and the TODO
  // evidence is the more specific fact.)
  if ((run.status === "failed" || run.status === "error") && hasUnadaptedEvidence(logs)) {
    return "unadapted";
  }
  if (run.status === "passed" || run.status === "failed") {
    if (hasZeroTestEvidence(logs)) return "no_tests";
    if (run.status === "passed" && hasInconclusiveEvidence(logs)) return "failed";
    return run.status;
  }
  // "error", "backend_unreachable", and anything unrecognized save as
  // "error" — unless the output proves the harness ran zero tests, in
  // which case the honest kind is "no_tests", not a failure.
  if (hasZeroTestEvidence(logs)) return "no_tests";
  return "error";
}

/**
 * The status a STORED row effectively carries, for counters, filters
 * and reused-run verdicts. Rows saved under the old vocabulary report
 * tests=0 runs and value-guard skips as "error"; when the stored output
 * carries the evidence, the row reclassifies on read. A "passed" row
 * whose output notes an inconclusive run reclassifies to "failed". Anything
 * else passes through unchanged.
 */
export function effectivePocStatus(
  status: string | null | undefined,
  output: string | null | undefined,
): string | null {
  if (!status) return status ?? null;
  // Scaffold aborts were filed as "failed" (the require reverted a test)
  // or "error" before the unadapted kind existed; the stored output's
  // TODO-abort message reclassifies them on read.
  if ((status === "error" || status === "failed") && hasUnadaptedEvidence(output)) {
    return "unadapted";
  }
  if (status === "passed" && hasInconclusiveEvidence(output)) {
    return "failed";
  }
  if (status === "error") {
    if (hasZeroTestEvidence(output)) return "no_tests";
    if (hasSkipSentinel(output)) return "skipped";
  }
  return status;
}

// ---------------------------------------------------------------------
// PoC provenance on the Finding (G8). The Finding record has always
// carried pocStatus / pocOutput / pocCode, but not WHERE the executed
// code came from (origin, owned by poc-evidence.ts) nor the verdict in
// this module's vocabulary — so every consumer re-derived both, or
// guessed. PocProvenance is the pair, and findingPocProvenance derives
// it for ANY stored row, old ones included:
//
// - verdict: effectivePocStatus over the stored status + output, so
//   old-vocabulary rows reclassify on read exactly like the counters.
// - origin: judged from the saved executed code itself. A run through
//   prepareFindingPoc saves a library template VERBATIM (templates are
//   complete Test contracts, passed through unchanged), so code that
//   contains a catalog template's source IS a template run; anything
//   else with saved code is finding-specific (wrapped snippet or
//   LLM-generated) — 'generated', the same line findingPocEvidence
//   draws. No saved code reads as 'template', matching its fallback
//   for code-less rows. (A generated PoC that embeds a template
//   verbatim reads as 'template' — it was one, whatever produced it.)
// ---------------------------------------------------------------------

export type PocProvenance = {
  origin: PocOrigin;
  verdict: SavedPocStatus | null;
};

const SAVED_POC_STATUS_SET: ReadonlySet<string> = new Set<SavedPocStatus>([
  "passed",
  "failed",
  "error",
  "no_tests",
  "skipped",
  "unadapted",
]);

/** Origin of executed PoC code, judged against the shipped catalog. */
export function pocOriginOfExecutedCode(code: string | null | undefined): PocOrigin {
  if (!code || !code.trim()) return "template";
  for (const source of Object.values(POC_FALLBACK_TEMPLATES)) {
    if (source && code.includes(source)) return "template";
  }
  return "generated";
}

/**
 * Provenance for a finding's recorded run, or null when the finding
 * has never been run (no stored status). Pure derivation — safe to
 * call at read time for every row a loader returns.
 */
export function findingPocProvenance(finding: {
  pocStatus?: string | null;
  pocOutput?: string | null;
  pocCode?: string | null;
}): PocProvenance | null {
  if (!finding.pocStatus) return null;
  const effective = effectivePocStatus(finding.pocStatus, finding.pocOutput);
  const verdict =
    effective && SAVED_POC_STATUS_SET.has(effective)
      ? (effective as SavedPocStatus)
      : null;
  return { origin: pocOriginOfExecutedCode(finding.pocCode), verdict };
}

// ---------------------------------------------------------------------
// The pre-run generation gate.
//
// Forge executes public/external functions whose names start with
// "test" in the matched contract. A prepared PoC with ZERO such
// functions can only produce a hollow tests=0 run — the historical
// source of the polluted "error" bucket (wrapPocSnippet passes a
// complete Test contract through unchanged, and a raw detector snippet
// that fails to wrap reaches the backend with no test function at
// all). The gate counts statically, gives the LLM ONE generation
// attempt to supply a real test function, and lets the caller save a
// "no_tests" outcome WITHOUT spending a fork run when it still has
// none.
// ---------------------------------------------------------------------

/**
 * Remove comments and string literals so name matching only sees code.
 * Single pass, escape-aware. (A test function cannot be declared inside
 * a literal in any real PoC; template-literal ${} expressions are
 * treated as string content, which is the conservative direction —
 * they can only hide a declaration, and the post-run zero-test
 * classification is the backstop.)
 */
function stripCommentsAndStrings(source: string): string {
  let out = "";
  let i = 0;
  const n = source.length;
  while (i < n) {
    const c = source[i];
    const next = source[i + 1] ?? "";
    if (c === "/" && next === "/") {
      while (i < n && source[i] !== "\n") i++;
    } else if (c === "/" && next === "*") {
      i += 2;
      while (i < n && !(source[i] === "*" && source[i + 1] === "/")) i++;
      i += 2;
    } else if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      i++;
      while (i < n && source[i] !== quote) {
        if (source[i] === "\\") i++;
        i++;
      }
      i++;
      out += " ";
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

/**
 * Count the test functions forge would execute from this source:
 * `function test…( … )` declarations with a body whose visibility is
 * public or external (forge does not run internal/private functions,
 * and a `;`-terminated declaration has no body to run). Commented-out
 * or string-contained "functions" do not count. testFail* names are
 * counted — forge's handling of them varies by version, and the
 * post-run classification (savedStatusFromRun) is the backstop if a
 * given forge runs none of them.
 */
export function countExecutableTestFunctions(source: string): number {
  if (!source) return 0;
  const code = stripCommentsAndStrings(source);
  const declRe = /function\s+(test[A-Za-z0-9_]*)\s*\(/g;
  let count = 0;
  let m: RegExpExecArray | null;
  while ((m = declRe.exec(code)) !== null) {
    if (m[1].length <= 4) continue; // the bare name "test" itself is not a test
    // Skip the parameter list (balanced parens).
    let depth = 0;
    let j = declRe.lastIndex - 1; // at the "("
    for (; j < code.length; j++) {
      if (code[j] === "(") depth++;
      else if (code[j] === ")") {
        depth--;
        if (depth === 0) {
          j++;
          break;
        }
      }
    }
    // The signature tail up to the body "{" or the terminating ";".
    let tail = "";
    for (; j < code.length && code[j] !== "{" && code[j] !== ";"; j++) {
      tail += code[j];
    }
    if (code[j] !== "{") continue; // declaration without a body
    if (/\b(internal|private)\b/.test(tail)) continue; // forge never runs these
    count++;
  }
  return count;
}

/** The explicit instruction handed to the LLM repair/generation
 *  machinery when a prepared PoC has no executable test function. */
export const NO_TESTS_GENERATION_INSTRUCTION =
  "The PoC below contains NO executable Foundry test function, so forge runs zero tests and there is no verdict. " +
  "Rewrite it as a complete, runnable Foundry test: the PoC contract must contain at least one public test function " +
  "whose name starts with `test` (for example `function testExploit() public { ... }`) that performs the exploit " +
  "against the target and asserts the outcome. Keep the existing attack logic; add the missing test function " +
  "around it. Return only the full corrected Solidity source.";

export type PocTestGateResult = {
  /** The source to run (or to save with a no_tests outcome): the
   *  generation result when one was produced, else the input. */
  testCode: string;
  /** Executable test functions in `testCode`. 0 means: do not run. */
  testCount: number;
  generationAttempted: boolean;
  generationNote: string | null;
};

/**
 * The shared pre-run gate: count the candidate source's executable
 * test functions; when there are none, invoke `generate` ONCE (the
 * caller's existing LLM repair/generation machinery, handed
 * NO_TESTS_GENERATION_INSTRUCTION) and recount its result. A throwing
 * or empty generation counts as "attempted, still none" — the caller
 * saves the no_tests outcome rather than an error.
 */
export async function ensureExecutablePocTests(
  testCode: string,
  generate: (instruction: string) => Promise<string | null | undefined>,
): Promise<PocTestGateResult> {
  const initial = countExecutableTestFunctions(testCode);
  if (initial > 0) {
    return { testCode, testCount: initial, generationAttempted: false, generationNote: null };
  }
  let generated: string | null = null;
  try {
    generated = (await generate(NO_TESTS_GENERATION_INSTRUCTION)) ?? null;
  } catch {
    generated = null;
  }
  if (generated && generated.trim()) {
    const recount = countExecutableTestFunctions(generated);
    return {
      testCode: generated,
      testCount: recount,
      generationAttempted: true,
      generationNote:
        recount > 0
          ? `Generation supplied ${recount} executable test function(s).`
          : "Generation attempt still produced no executable test function.",
    };
  }
  return {
    testCode,
    testCount: 0,
    generationAttempted: true,
    generationNote: "Generation attempt returned no source.",
  };
}

// ---------------------------------------------------------------------
// The unadapted-template pre-check.
//
// Thirteen fallback templates ship with required TODO constants at
// zero (index.json `todo`, emitted as POC_FALLBACK_TODO_REQUIREMENTS):
// an OWNER, a ROUTER, a MESSAGE_HASH, a PRICE… Run as shipped — which
// is what the cap-1 direct paths do — the template aborts on its own
// require before judging the target, and the abort used to file as
// "failed" or "error". Neither is true: no verdict about the target
// exists. The direct paths therefore run this check BEFORE the
// backend: when the source IS one of those templates (identity by
// normalized-source match with TODO initializers blanked on both
// sides — poc-wrap passes complete test contracts through unchanged,
// so a template reaches a run path textually intact, and blanking
// keeps partially adapted variants identifiable) and any required
// constant is still zero, the run saves as "unadapted" without a
// backend call.
// ---------------------------------------------------------------------

let normalizedTemplateCache: Map<string, string> | null = null;

/**
 * Replace every assignment to one of `names` with a canonical zero
 * assignment. Identification compares sources with their TODO
 * initializers blanked on BOTH sides, so a partially or fully adapted
 * template still identifies as that template — the constants' values
 * are exactly the adaptation points, and the filled-analysis below
 * judges them separately. (A constant declared with no initializer at
 * all — 36's `proof` — has nothing to blank; a variant that
 * initializes it simply stops identifying here and is still caught on
 * save by the TODO-abort output evidence if it aborts.)
 */
function blankTodoInitializers(code: string, names: readonly string[]): string {
  let out = code;
  for (const name of names) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    out = out.replace(new RegExp(`\\b${escaped}\\s*=(?![=>])\\s*[^;]+;`, "g"), `${name} = 0;`);
  }
  return out;
}

function normalizedTemplateSources(): Map<string, string> {
  if (normalizedTemplateCache) return normalizedTemplateCache;
  const map = new Map<string, string>();
  for (const [file, names] of Object.entries(POC_FALLBACK_TODO_REQUIREMENTS)) {
    const source = POC_FALLBACK_TEMPLATES[file];
    if (source) {
      map.set(
        file,
        blankTodoInitializers(stripCommentsAndStrings(source), names).replace(/\s+/g, ""),
      );
    }
  }
  normalizedTemplateCache = map;
  return map;
}

/** A zero initializer: literal 0 / 0x0…0, a numeric type cast of one,
 *  or an empty dynamic allocation. Anything else counts as filled. */
function isZeroInitializer(expr: string): boolean {
  const e = expr.replace(/\s+/g, "");
  if (e === "0" || e === "0x0") return true;
  if (/^0x0+$/.test(e)) return true;
  const cast = e.match(/^(?:address|bytes32|uint256|uint|int256|int)\((.*)\)$/);
  if (cast) return isZeroInitializer(cast[1]);
  if (e === "newbytes(0)" || e === "newbytes[](0)" || e === "newbytes32[](0)") return true;
  return false;
}

/**
 * Whether a TODO constant counts as filled in this source. Adaptation
 * in this library means editing the constant (the templates direct the
 * adapter to the declaration), so ANY non-zero assignment to the name
 * fills it; a declaration holding only zero initializers — or no
 * initializer at all (36's `bytes32[] public proof;`) — does not. An
 * array constant adapted by pushing elements in setUp also counts.
 */
function todoConstantFilled(code: string, name: string): boolean {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // (?!=|>) excludes == comparisons and => arrows: only a real
  // assignment's initializer counts.
  const assignRe = new RegExp(`\\b${escaped}\\s*=(?![=>])\\s*([^;]+);`, "g");
  let sawAssignment = false;
  let m: RegExpExecArray | null;
  while ((m = assignRe.exec(code)) !== null) {
    sawAssignment = true;
    if (!isZeroInitializer(m[1])) return true;
  }
  if (sawAssignment) return false;
  if (new RegExp(`\\b${escaped}\\s*\\.\\s*push\\s*\\(`).test(code)) return true;
  return false;
}

export type UnadaptedTemplateCheck = {
  /** The library file the source was identified as. */
  file: string;
  /** Required TODO constants still at their zero shipped values. */
  unfilled: string[];
};

/**
 * Identify `source` as a fallback template with unfilled TODO
 * constants. Returns null for non-template sources, for templates
 * with no TODO requirements, and for templates whose constants are
 * all filled (an adapted template proceeds to the backend normally).
 */
export function unadaptedTemplateCheck(source: string): UnadaptedTemplateCheck | null {
  if (!source || !source.trim()) return null;
  const code = stripCommentsAndStrings(source);
  for (const [file, templateNormalized] of normalizedTemplateSources()) {
    const required = POC_FALLBACK_TODO_REQUIREMENTS[file] ?? [];
    const normalized = blankTodoInitializers(code, required).replace(/\s+/g, "");
    if (normalized !== templateNormalized && !normalized.includes(templateNormalized)) continue;
    const unfilled = required.filter((name) => !todoConstantFilled(code, name));
    return unfilled.length > 0 ? { file, unfilled } : null;
  }
  return null;
}

/** The saved output text for a pre-check short-circuit: names the
 *  template and the unfilled constants, and carries the sentinel the
 *  read-time reclassification keys on. */
export function unadaptedTemplateOutput(file: string, unfilled: string[]): string {
  return (
    `${UNADAPTED_SENTINEL} ${file}: required TODO constant(s) still unfilled: ${unfilled.join(", ")}. ` +
    "Run as shipped, the template aborts on its own precondition before judging the target, so no verdict exists. " +
    "Saved as unadapted — adapt the template's TODO constants to the target (or let the AI path adapt it) and re-run."
  );
}
