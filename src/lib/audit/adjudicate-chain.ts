// src/lib/audit/adjudicate-chain.ts
//
// The one-action adjudication chain: fetch → AI review → PoC → run →
// save → suggestion, orchestrated client-side exactly like the existing
// Run flows (the browser talks to the loopback Foundry backend; the AI
// review and the saves go through server functions). Both call sites —
// the workbench findings tab and the PoC Audits page — inject their own
// state plumbing as `deps`; everything decision-shaped lives in the pure
// planner (adjudication.ts) so the skip behaviour is unit-tested, and
// this module only sequences effects.
//
// Idempotency, concretely:
// - a finding that already HAS a disposition short-circuits (unless the
//   caller forces a redo) — nothing is called at all;
// - an existing AI review for the scan is reused — no second OpenRouter
//   call for the same scan;
// - a stored terminal run whose source digest matches the PoC that
//   would run is reused as the verdict — the backend is not re-executed;
// - the save goes through saveFindingPocResult, whose run row is keyed
//   by (finding, source digest) with an upsert, so even a raced double
//   save cannot duplicate the run of record.
//
// The chain NEVER writes a disposition. It ends at a SUGGESTION, which
// the UI offers as a one-tap accept; the human tap is what persists.
import { sha3_256 } from "js-sha3";
import {
  planAdjudication,
  prepareFindingPoc,
  suggestDispositionForVerdict,
  type AuditorDisposition,
  type FindingDisposition,
  type PocVerdict,
} from "./adjudication.ts";
import { pocRunKey } from "./poc-run-key.ts";
import {
  effectivePocStatus,
  ensureExecutablePocTests,
  savedStatusFromRun,
} from "./poc-outcome.ts";
import type { AiSecurityReview } from "./ai-review.server.ts";
import type { Finding } from "./types.ts";

/** A stored finding_poc_runs row, reduced to what the chain needs. */
export type AdjudicationRunRecord = {
  id: string;
  status: string;
  sourceDigest: string;
  output: string;
  durationMs: number;
  createdAt: string;
};

export type AdjudicationContext = {
  scanId: string;
  /** The finding under adjudication, carrying its DATABASE id
   *  (`${scanId}:${ord}`) — dispositions and runs key on it. */
  finding: Finding;
  /** The scan's source/body (the "fetch" step's product). "" when the
   *  scan could not be loaded — the chain then degrades to a
   *  needs-more-info outcome instead of failing. */
  body: string;
  /** All findings of the scan (AI review input). */
  findings: Finding[];
  contractName: string;
  targetAddress: string | null;
  chainId: string | null;
  /** The scan's existing AI review, or null — null is what makes the
   *  chain spend an OpenRouter call. */
  aiReview: AiSecurityReview | null;
  /** The finding's current disposition of record, or null. */
  disposition: FindingDisposition | null;
  /** The per-finding "redo": overrides every skip in the planner. The
   *  stored disposition is still not touched — a redo lands on a fresh
   *  suggestion the human may accept or ignore. */
  force?: boolean;
};

export type AdjudicationDeps = {
  requestAiReview: (input: {
    contractName: string;
    body: string;
    findings: Finding[];
  }) => Promise<AiSecurityReview>;
  /** Persist a freshly generated review onto the scan (best-effort —
   *  a persist failure is reported in the outcome message, never fatal). */
  persistAiReview: (review: AiSecurityReview) => Promise<void>;
  listRuns: (findingId: string) => Promise<AdjudicationRunRecord[]>;
  runPoc: (input: {
    address: string;
    chainId?: string;
    testCode: string;
  }) => Promise<{ status: string; logs: string; durationMs: number; executedSource?: string }>;
  repairPoc: (input: {
    contractName: string;
    originalCode: string;
    errorLogs: string;
    body: string;
  }) => Promise<string>;
  isCompileError: (logs: string) => boolean;
  saveRun: (record: {
    findingId: string;
    scanId: string;
    status: PocVerdict;
    source: string;
    output: string;
    durationMs: number;
    chainId: string | null;
    targetAddress: string | null;
  }) => Promise<void>;
  onProgress?: (notice: string) => void;
  /** Per-step state transitions for the queue/card step display
   *  (fetch ✓ / llm ✓ / harness ✓ / saved ✓). */
  onStep?: (step: ChainStep, state: ChainStepState | "running") => void;
};

/** The pipeline's four steps, in order. A chain that does not complete
 *  every step is INCOMPLETE and reports the first step it stopped at —
 *  it is never presented as adjudicated. */
export type ChainStep = "fetch" | "llm" | "harness" | "saved";

export type ChainStepState = "done" | "reused" | "failed" | "skipped";

export const CHAIN_STEP_ORDER: readonly ChainStep[] = ["fetch", "llm", "harness", "saved"] as const;

function summarizeSteps(steps: Record<ChainStep, ChainStepState>): {
  complete: boolean;
  stoppedAt: ChainStep | null;
} {
  for (const step of CHAIN_STEP_ORDER) {
    const s = steps[step];
    if (s !== "done" && s !== "reused") return { complete: false, stoppedAt: step };
  }
  return { complete: true, stoppedAt: null };
}

export type AdjudicationOutcome = {
  kind: "suggested" | "already_adjudicated" | "no_poc" | "error";
  verdict: PocVerdict | null;
  /** The disposition the UI should offer for one-tap acceptance. For
   *  `already_adjudicated` this is the disposition already of record. */
  suggestion: AuditorDisposition;
  /** Full run log for the inline finding card (fresh or reused). */
  output: string | null;
  /** The exact PoC source that ran (or would run). */
  testCode: string | null;
  reviewStep: "reused" | "generated" | "failed" | "skipped";
  runStep: "reused" | "executed" | "skipped" | "failed";
  saveError: string | null;
  /** Final state of each pipeline step. */
  steps: Record<ChainStep, ChainStepState>;
  /** True only when every step completed (done or reused) — or when
   *  the finding was already adjudicated by a human earlier. An
   *  incomplete chain may still carry a verdict + suggestion, but the
   *  UI must present it as INCOMPLETE (see `stoppedAt`), never as a
   *  finished adjudication. */
  complete: boolean;
  /** The first step that did not complete, or null when complete. */
  stoppedAt: ChainStep | null;
  message: string;
};

/** Outcome for a chain that could not even start (e.g. the caller could
 *  not load the scan — the fetch step failed before the chain ran). */
export function failedAdjudicationOutcome(message: string, stoppedAt: ChainStep): AdjudicationOutcome {
  const steps: Record<ChainStep, ChainStepState> = {
    fetch: "skipped",
    llm: "skipped",
    harness: "skipped",
    saved: "skipped",
  };
  steps[stoppedAt] = "failed";
  return {
    kind: "error",
    verdict: "error",
    suggestion: "needs_more_info",
    output: message,
    testCode: null,
    reviewStep: "skipped",
    runStep: "skipped",
    saveError: null,
    steps,
    complete: false,
    stoppedAt,
    message,
  };
}

// Forge exits 0 when no test matches, so a "passed" with zero executed
// tests is a hollow PASS, never a verdict (the standing repo lesson).
// The status mapping itself lives in poc-outcome.ts, shared with the
// PoC Audits page: a hollow PASS maps to "no_tests" (not a verdict, not
// an error), a value-guard skip stays "skipped", and only real failures
// (compile, backend, RPC/fork, timeout) map to "error". The chain used
// to fold everything non-verdict into "error" — that conflation is
// what polluted the Errors bucket with skips and zero-test runs.
function verdictFromRunStatus(status: string, logs: string): PocVerdict {
  return savedStatusFromRun({ status, logs });
}

function verdictFromStoredStatus(status: string, output?: string | null): PocVerdict {
  // Stored rows predate the no_tests/skipped vocabulary (both were
  // saved as "error"); effectivePocStatus reclassifies them on read
  // when the stored output carries the evidence.
  const eff = effectivePocStatus(status, output);
  if (eff === "passed" || eff === "failed" || eff === "no_tests" || eff === "skipped") return eff;
  return "error";
}

/**
 * Terminal-outcome completion override. Most outcomes derive `complete`
 * from the step states (any skipped step = incomplete), but two
 * outcomes are complete BY CONSTRUCTION even though the harness step
 * ends "skipped": the no_tests gate save (nothing executable existed
 * to run) and a value-guard skip (nothing at stake to test). In both,
 * the pipeline did everything applicable and persisted a first-class
 * outcome — marking them INCOMPLETE would present a deliberate,
 * recorded outcome as a pipeline stoppage, the same misclassification
 * this vocabulary exists to remove. Applied only after a successful
 * save; a failed save leaves the outcome incomplete at "saved".
 */
function asTerminal(outcome: AdjudicationOutcome): AdjudicationOutcome {
  return { ...outcome, complete: true, stoppedAt: null };
}

export async function runAdjudicationChain(
  ctx: AdjudicationContext,
  deps: AdjudicationDeps,
): Promise<AdjudicationOutcome> {
  const progress = (notice: string) => deps.onProgress?.(notice);
  const step = (s: ChainStep, state: ChainStepState | "running") => deps.onStep?.(s, state);
  const finding = ctx.finding;

  // --- Fetch step ------------------------------------------------------
  // The caller loads the scan (source/ABI) before invoking the chain;
  // inside the chain the fetch product is the body. No body means the
  // fetch produced nothing usable: the LLM step cannot run and the
  // chain is incomplete at fetch, whatever else it manages to do.
  const steps: Record<ChainStep, ChainStepState> = {
    fetch: ctx.body.trim() ? "done" : "failed",
    llm: "skipped",
    harness: "skipped",
    saved: "skipped",
  };
  step("fetch", steps.fetch);

  progress("Preparing the PoC and checking what's already done…");
  const prepared = prepareFindingPoc(finding);
  const candidateDigest = prepared ? pocRunKey(finding.id, prepared.testCode).digest : null;

  let runs: AdjudicationRunRecord[] = [];
  try {
    runs = await deps.listRuns(finding.id);
  } catch {
    // A failed run-history read must not block adjudication — the save
    // still dedupes server-side on (finding, digest). Worst case the
    // chain re-executes a proof that was already run.
    runs = [];
  }

  const plan = planAdjudication({
    hasDisposition: Boolean(ctx.disposition),
    hasReview: Boolean(ctx.aiReview),
    candidateDigest,
    existingRuns: runs.map((r) => ({ digest: r.sourceDigest, status: r.status })),
    force: ctx.force,
  });

  if (plan.alreadyAdjudicated && ctx.disposition) {
    // Complete by definition: a human already adjudicated this finding.
    // The steps stay "skipped" — the pipeline did not run — but the
    // finding is not incomplete; it has a verdict of record.
    step("llm", "skipped");
    step("harness", "skipped");
    step("saved", "skipped");
    return {
      kind: "already_adjudicated",
      verdict: null,
      suggestion: ctx.disposition.disposition,
      output: null,
      testCode: prepared?.testCode ?? null,
      reviewStep: "skipped",
      runStep: "skipped",
      saveError: null,
      steps,
      complete: true,
      stoppedAt: null,
      message: `Already adjudicated — disposition of record: ${ctx.disposition.disposition}. Use Redo to re-run the chain.`,
    };
  }

  // --- LLM step ---------------------------------------------------------
  let reviewStep: AdjudicationOutcome["reviewStep"] = "skipped";
  if (plan.reuseReview) {
    reviewStep = "reused";
    steps.llm = "reused";
  } else if (ctx.body.trim()) {
    progress("Asking OpenRouter for the AI review…");
    step("llm", "running");
    try {
      const review = await deps.requestAiReview({
        contractName: ctx.contractName,
        body: ctx.body,
        findings: ctx.findings,
      });
      reviewStep = "generated";
      steps.llm = "done";
      try {
        await deps.persistAiReview(review);
      } catch {
        // The review exists for this session even if the save failed;
        // the chain continues — the PoC verdict is the load-bearing part.
      }
    } catch {
      reviewStep = "failed"; // advisory step — the PoC can still prove
      steps.llm = "failed";
    }
  }
  step("llm", steps.llm);

  const finish = (
    partial: Omit<AdjudicationOutcome, "steps" | "complete" | "stoppedAt">,
  ): AdjudicationOutcome => {
    const { complete, stoppedAt } = summarizeSteps(steps);
    return { ...partial, steps, complete, stoppedAt };
  };

  // --- PoC preparation --------------------------------------------------
  if (!prepared) {
    step("harness", "skipped");
    step("saved", "skipped");
    return finish({
      kind: "no_poc",
      verdict: null,
      suggestion: suggestDispositionForVerdict(null),
      output: null,
      testCode: null,
      reviewStep,
      runStep: "skipped",
      saveError: null,
      message:
        "No runnable PoC could be prepared for this finding (no exploit snippet and no matching template), so there is no verdict to suggest from.",
    });
  }

  if (plan.reuseRun) {
    const stored = runs.find((r) => r.sourceDigest === plan.reuseRun?.digest);
    const verdict = verdictFromStoredStatus(plan.reuseRun.status, stored?.output);
    steps.harness = "reused";
    steps.saved = "reused"; // the run of record is already persisted
    step("harness", "reused");
    step("saved", "reused");
    return finish({
      kind: "suggested",
      verdict,
      suggestion: suggestDispositionForVerdict(verdict),
      output: stored?.output ?? null,
      testCode: prepared.testCode,
      reviewStep,
      runStep: "reused",
      saveError: null,
      message: `Already run — this exact PoC was executed before with verdict ${verdict}; not re-executed.`,
    });
  }

  if (!ctx.targetAddress) {
    steps.harness = "failed";
    step("harness", "failed");
    step("saved", "skipped");
    return finish({
      kind: "error",
      verdict: "error",
      suggestion: suggestDispositionForVerdict("error"),
      output: "This scan has no target address, so the PoC cannot run on a fork. Fetch the contract by address (or load an address audit) and adjudicate again.",
      testCode: prepared.testCode,
      reviewStep,
      runStep: "failed",
      saveError: null,
      message: "No target address on the scan — the fork run needs one.",
    });
  }

  // --- Generation gate ----------------------------------------------------
  // A prepared PoC with ZERO executable test functions can only produce
  // a hollow tests=0 run (forge matches nothing) — historically saved
  // as an "error" it never was. Give the LLM one generation attempt to
  // supply a real test function; if it still has none, save the outcome
  // as 'no_tests' WITHOUT calling the backend (no wasted fork run). The
  // shared gate lives in poc-outcome.ts; the PoC Audits page's Run path
  // applies the identical gate.
  const gate = await ensureExecutablePocTests(prepared.testCode, async (instruction) => {
    try {
      return await deps.repairPoc({
        contractName: ctx.contractName,
        originalCode: prepared.testCode,
        errorLogs: instruction,
        body: ctx.body,
      });
    } catch {
      return null;
    }
  });
  if (gate.testCount === 0) {
    steps.harness = "skipped"; // deliberately not executed — nothing to execute
    step("harness", "skipped");
    const gateLogs = `Finding input SHA3-256: ${sha3_256(finding.exploitSolidity ?? "")}\n${
      prepared.note ? `${prepared.note}\n` : ""
    }[SmartPoC] Not run — the prepared PoC contains no executable test function, so forge would run 0 tests. ${
      gate.generationNote ?? ""
    } Saved as no_tests: a generation gap, not an error and not a verdict on the finding.`;
    let saveError: string | null = null;
    try {
      await deps.saveRun({
        findingId: finding.id,
        scanId: ctx.scanId,
        status: "no_tests",
        source: gate.testCode,
        output: gateLogs,
        durationMs: 0,
        chainId: ctx.chainId,
        targetAddress: ctx.targetAddress,
      });
      steps.saved = "done";
    } catch (err) {
      saveError = err instanceof Error ? err.message : String(err);
      steps.saved = "failed";
    }
    step("saved", steps.saved);
    const outcome = finish({
      kind: "suggested",
      verdict: "no_tests",
      suggestion: suggestDispositionForVerdict("no_tests"),
      output: gateLogs,
      testCode: gate.testCode,
      reviewStep,
      runStep: "skipped",
      saveError,
      message:
        "PoC generation produced no executable test function for this finding — saved as no-tests without calling the backend. Not evidence about the bug — suggesting Needs info.",
    });
    // Terminal outcome (see asTerminal) once the save landed.
    return saveError ? outcome : asTerminal(outcome);
  }

  // --- Harness step (with one LLM repair on a compile error) ------------
  progress("Running the PoC on the Foundry backend…");
  step("harness", "running");
  let testCode = gate.testCode;
  let verdict: PocVerdict;
  let logs: string;
  let durationMs = 0;
  // The harness STEP state is about whether the harness actually ran:
  // a returned error verdict (compile failure, zero tests) still means
  // it ran; a transport throw, an unreachable backend, or a deliberate
  // skip (zero-value target) means it did not.
  let harnessState: ChainStepState = "done";
  try {
    let poc = await deps.runPoc({
      address: ctx.targetAddress,
      chainId: ctx.chainId ?? undefined,
      testCode,
    });
    verdict = verdictFromRunStatus(poc.status, poc.logs ?? "");
    logs = poc.logs ?? "";
    durationMs = poc.durationMs ?? 0;
    if (poc.status === "backend_unreachable") harnessState = "failed";
    if (poc.status === "skipped") harnessState = "skipped";
    if (verdict === "error" && deps.isCompileError(logs)) {
      progress("PoC failed to compile — asking the model to repair it…");
      try {
        const fixed = await deps.repairPoc({
          contractName: ctx.contractName,
          originalCode: testCode,
          errorLogs: logs,
          body: ctx.body,
        });
        if (fixed && fixed.trim() && fixed !== testCode) {
          testCode = fixed;
          poc = await deps.runPoc({
            address: ctx.targetAddress,
            chainId: ctx.chainId ?? undefined,
            testCode,
          });
          verdict = verdictFromRunStatus(poc.status, poc.logs ?? "");
          logs = poc.logs ?? "";
          durationMs = poc.durationMs ?? 0;
          testCode = poc.executedSource ?? testCode;
          harnessState = poc.status === "backend_unreachable" ? "failed" : poc.status === "skipped" ? "skipped" : "done";
        }
      } catch {
        // Repair failure is not a new verdict — keep the compile error.
      }
    } else {
      testCode = poc.executedSource ?? testCode;
    }
  } catch (err) {
    verdict = "error";
    logs = `Execution error: ${err instanceof Error ? err.message : String(err)}`;
    testCode = prepared.testCode;
    harnessState = "failed";
  }
  steps.harness = harnessState;
  step("harness", steps.harness);

  const displayLogs = `Finding input SHA3-256: ${sha3_256(finding.exploitSolidity ?? "")}\n${
    prepared.note ? `${prepared.note}\n` : ""
  }${logs}`;

  // --- Save step ----------------------------------------------------------
  let saveError: string | null = null;
  try {
    await deps.saveRun({
      findingId: finding.id,
      scanId: ctx.scanId,
      status: verdict,
      source: testCode,
      output: displayLogs,
      durationMs,
      chainId: ctx.chainId,
      targetAddress: ctx.targetAddress,
    });
    steps.saved = "done";
  } catch (err) {
    saveError = err instanceof Error ? err.message : String(err);
    steps.saved = "failed";
  }
  step("saved", steps.saved);

  const outcome = finish({
    kind: "suggested",
    verdict,
    suggestion: suggestDispositionForVerdict(verdict),
    output: displayLogs,
    testCode,
    reviewStep,
    runStep: "executed",
    saveError,
    message:
      verdict === "passed"
        ? "PoC reproduced on the fork — suggesting Confirmed."
        : verdict === "failed"
          ? "PoC did not reproduce on the fork — suggesting False positive."
          : verdict === "no_tests"
            ? "The executed PoC evidenced zero tests, so there is no verdict — suggesting Needs info."
            : verdict === "skipped"
              ? "The run was skipped — the target holds no value at stake, so nothing was tested. A skip is not evidence about the bug — suggesting Needs info."
              : "The run ended in an error, which is not evidence either way — suggesting Needs info.",
  });
  // A value-guard skip is a terminal outcome (see asTerminal): the run
  // was deliberately not executed, the outcome is of record, and the
  // pipeline stopped for a reason that is not a failure.
  return verdict === "skipped" && !saveError ? asTerminal(outcome) : outcome;
}
