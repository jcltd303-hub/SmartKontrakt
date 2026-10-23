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

/** The statuses a run can be SAVED under (findings.poc_status /
 *  finding_poc_runs.status). The transport-level "backend_unreachable"
 *  is deliberately not one of them — it saves as "error". */
export type SavedPocStatus = "passed" | "failed" | "error" | "no_tests" | "skipped";

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

/**
 * Map a FRESH run result to the status it is saved under. The run's own
 * status field is authoritative here — a value-guard skip arrives as
 * status "skipped", never embedded in an "error" — except for the
 * hollow-verdict guard: a "passed"/"failed" whose output evidences
 * zero executed tests is not a verdict and becomes "no_tests".
 */
export function savedStatusFromRun(run: { status: string; logs?: string | null }): SavedPocStatus {
  const logs = run.logs ?? "";
  if (run.status === "skipped") return "skipped";
  if (run.status === "no_tests") return "no_tests";
  if (run.status === "passed" || run.status === "failed") {
    return hasZeroTestEvidence(logs) ? "no_tests" : run.status;
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
 * carries the evidence, the row reclassifies on read. Anything else
 * passes through unchanged.
 */
export function effectivePocStatus(
  status: string | null | undefined,
  output: string | null | undefined,
): string | null {
  if (!status) return status ?? null;
  if (status === "error") {
    if (hasZeroTestEvidence(output)) return "no_tests";
    if (hasSkipSentinel(output)) return "skipped";
  }
  return status;
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
