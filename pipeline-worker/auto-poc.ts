/**
 * Auto-PoC for the pipeline worker — Jer's rule: when an entry's
 * initial pipeline scores include a high or critical finding, the
 * worker does not wait for a human to open the PoC Audits page. It
 * automatically LLM-generates a PoC for each eligible finding, runs it
 * against the Foundry backend, and saves the verdict to Supabase.
 *
 * Nothing here re-implements the pipeline: generation, the executable-
 * test gate, the unadapted-template pre-check, the backend run and the
 * save are the adjudication chain itself (src/lib/audit/
 * adjudicate-chain.ts) — the same machinery the workbench and the PoC
 * Audits page drive — with its deps wired to the server-side cores
 * those surfaces reach through server functions:
 *   review    generateAiSecurityReview (ai-review.server.ts)
 *   repair    repairPocCode (deep-agent.server.ts) — the chain's LLM
 *             generation attempt and its compile repair both ride it
 *   run       runPocWithRpcRetries (foundry-backend.ts)
 *   save      saveFindingPocResult (persist.server.ts) — updates the
 *             finding row + upserts the finding_poc_runs row, with the
 *             chain's G6 suggestion semantics untouched
 *   history   listFindingPocRuns (persist.server.ts)
 *
 * Worker-specific behaviour is only the ORCHESTRATION around the
 * chain:
 * - Trigger: the saved report carries >= 1 finding at high/critical.
 *   Eligibility is the PoC feed's own rule (pocAuditEligibility at
 *   scope "critical_and_high"): presence-only findings are excluded
 *   unless corroborated — the report's own fields plus the analyzed
 *   body serve as the G3 source evidence, exactly as the feed resolves
 *   it. Findings that already carry a poc_status are skipped.
 * - The trigger reads the report's stored severities as analyzeAddress
 *   saved them — post-calibration, post-resnet-recompute. No special
 *   ResNet handling: resnet's term is already inside those severities'
 *   risk score and the findings themselves are unchanged by it.
 * - Sequential: findings run one chain at a time; the backend runs
 *   one PoC at a time, so nothing here parallelizes backend calls.
 * - Identical-draft dedupe: within one entry, sibling findings of the
 *   same detector routinely prepare byte-identical PoC code (one
 *   template-derived draft per finding). The first execution's
 *   outcome is a determination about that CODE — re-running the same
 *   code against the same target proves nothing and burns a backend
 *   slot per sibling (Jer's 2026-10-25 run: 10 identical
 *   erc20-unchecked runs on one address). So the code that would be
 *   sent to the backend is hashed (SHA-256 — the digest the SmartPoC
 *   run header prints) and a repeat within the entry is NOT executed:
 *   the sibling saves the same verdict with the shared run named in
 *   its output, and the save is tallied as "shared", never as an
 *   attempt. Only code-determined outcomes are shared (the verdicts,
 *   no_tests, the value-guard skip, a compile error); infra outcomes
 *   (backend unreachable, RPC/fork failure) are never cached — they
 *   carry no information about the code.
 * - Per-run cap (autoPocCap, default 25; 0 = unlimited): the cap
 *   counts BACKEND ATTEMPTS — findings whose chain actually sent new
 *   code to the backend. Shared saves consume no slot. The cap is
 *   checked before each finding's chain (sharing can only be known
 *   after generation), so once the backend budget is spent the
 *   entry's remaining findings wait — logged once, pipeline
 *   continues static-only.
 * - Circuit breaker: 3 CONSECUTIVE infra outcomes (backend
 *   unreachable / RPC-or-fork failure — an "error" verdict that is
 *   not attributable to the PoC) trip it for the rest of the run;
 *   logged once, pipeline continues. Compile errors, verdicts and
 *   generation gaps are NOT infra — they reset the counter.
 * - Never throws: a failed generation saves 'error' honestly through
 *   the chain, a failed save is counted and logged, and no outcome
 *   fails the pipeline entry — the static record already landed.
 */

import { createHash } from "node:crypto";

import { runAdjudicationChain } from "../src/lib/audit/adjudicate-chain.ts";
import type {
  AdjudicationOutcome,
  AdjudicationRunRecord,
} from "../src/lib/audit/adjudicate-chain.ts";
import { pocAuditEligibility, type PocVerdict } from "../src/lib/audit/adjudication.ts";
import { generateAiSecurityReview } from "../src/lib/audit/ai-review.server.ts";
import type { AiSecurityReview } from "../src/lib/audit/ai-review.server.ts";
import { repairPocCode } from "../src/lib/audit/deep-agent.server.ts";
import {
  isPocCompileError,
  isRpcOrForkFailure,
  runPocWithRpcRetries,
} from "../src/lib/audit/foundry-backend.ts";
// persist.server.ts is imported LAZILY (inside the leaf defaults
// below), never statically: it carries an extensionless import
// (./bulk-persist.server) that only the bundler and tsx resolve, so a
// static import would make this module unloadable under plain Node —
// including the unit tests, which fake the persist leaves anyway. The
// worker runs under tsx, where the dynamic import resolves exactly
// like worker.ts's own persist imports.
import { externalTokenCandidate, fourbyteForStoredReport } from "../src/lib/audit/poc-audit-llm.ts";
import type { FourbyteResults } from "../src/lib/audit/fourbyte.ts";
import type { Finding, Report } from "../src/lib/audit/types.ts";

export const WORKER_AUTO_POC_DEFAULT_CAP = 25;
/** Consecutive infra outcomes that trip the per-run circuit breaker. */
export const WORKER_AUTO_POC_BREAKER_THRESHOLD = 3;

export type AutoPocTally = {
  /** Findings whose chain sent at least one new PoC to the backend —
   *  the cap counts these (see the header's dedupe/cap rules). */
  attempted: number;
  passed: number;
  failed: number;
  errors: number;
  skipped: number;
  /** Findings saved from an identical-code sibling's run instead of
   *  a backend execution of their own (dedupe — see the header). */
  shared: number;
};

/** Per-run auto-PoC state, owned by worker.ts (reset on every /start). */
export type AutoPocRunState = {
  tally: AutoPocTally;
  /** Consecutive infra outcomes — reset by any non-infra outcome. */
  consecutiveInfra: number;
  /** Breaker tripped: no more auto-PoC this run. */
  breakerTripped: boolean;
  capLogged: boolean;
  breakerLogged: boolean;
};

export function newAutoPocRunState(): AutoPocRunState {
  return {
    tally: { attempted: 0, passed: 0, failed: 0, errors: 0, skipped: 0, shared: 0 },
    consecutiveInfra: 0,
    breakerTripped: false,
    capLogged: false,
    breakerLogged: false,
  };
}

/** True when the per-run attempt cap is reached (cap 0 = unlimited). */
export function autoPocCapReached(state: AutoPocRunState, cap: number): boolean {
  return cap > 0 && state.tally.attempted >= cap;
}

/**
 * SHA-256 hex of the exact PoC source — the same digest the SmartPoC
 * run header prints (`SHA-256: …`, foundry-backend.ts) — computed
 * here over the code that would be sent to the backend, so an
 * identical draft is recognizable before it is sent twice.
 */
export function autoPocCodeHash(testCode: string): string {
  return createHash("sha256").update(testCode).digest("hex");
}

/** A backend result as the chain's runPoc dep returns it. */
type BackendRunResult = { status: string; logs: string; durationMs: number; executedSource?: string };

/**
 * Is this backend outcome a determination about the CODE — safe to
 * share with a sibling finding whose generated code is byte-identical?
 * The real verdicts (passed/failed), the zero-test outcome and the
 * value-guard skip all are; so is a compile error, which is a
 * property of the source alone (the sibling's chain still gets its
 * own repair attempt on top of the shared logs). Infra outcomes are
 * NOT: backend_unreachable and RPC/fork failures describe the
 * environment, not the code, and sharing them would save a verdict
 * the code never earned. This mirrors the terminal set the chain's
 * own planner reuses for a single finding (planAdjudication), minus
 * the infra-ambiguous "error".
 */
function isShareableRunResult(r: BackendRunResult): boolean {
  if (r.status === "passed" || r.status === "failed" || r.status === "no_tests" || r.status === "skipped") {
    return true;
  }
  if (r.status === "error") return isPocCompileError(r.logs) && !isRpcOrForkFailure(r.logs);
  return false;
}

/** One executed run of an entry, remembered for identical-code siblings. */
type SharedRun = { result: BackendRunResult; firstFindingId: string };

export type AutoPocCandidate = { finding: Finding; ord: number };

/**
 * The findings of one saved entry that auto-PoC runs for, in report
 * order: severity high or critical (the trigger), PoC-eligible under
 * the feed's rules (pocAuditEligibility — presence-only excluded
 * unless corroborated), and not already carrying a verdict. `source`
 * is the analyzed body (the scan's stored body): the G3 corroboration
 * evidence for presence-family findings, as the feed resolves it.
 */
export function selectAutoPocFindings(report: Report, source: string): AutoPocCandidate[] {
  const out: AutoPocCandidate[] = [];
  report.findings.forEach((finding, ord) => {
    if (finding.pocStatus) return; // a verdict of record already exists
    const { eligible } = pocAuditEligibility(finding, "critical_and_high", source);
    if (eligible) out.push({ finding, ord });
  });
  return out;
}

/**
 * The injectable leaf deps. Defaults wire the real server-side cores;
 * tests substitute fakes for the leaves and still exercise the REAL
 * adjudication chain end to end.
 */
export type AutoPocDeps = {
  runChain: typeof runAdjudicationChain;
  generateReview: (
    contractName: string,
    body: string,
    findings: Finding[],
    fourbyte: FourbyteResults | undefined,
  ) => Promise<AiSecurityReview>;
  persistReview: (scanId: string, review: AiSecurityReview) => Promise<void>;
  repair: (
    contractName: string,
    originalCode: string,
    errorLogs: string,
    body: string,
  ) => Promise<{ fixedCode: string }>;
  runBackend: (
    backendUrl: string,
    input: { address: string; chainId: string; testCode: string; tokenAddress?: string },
  ) => Promise<{ status: string; logs: string; durationMs: number; executedSource?: string }>;
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
  listRuns: (findingId: string) => Promise<AdjudicationRunRecord[]>;
  log: (line: string) => void;
};

export const defaultAutoPocDeps: AutoPocDeps = {
  runChain: runAdjudicationChain,
  generateReview: generateAiSecurityReview,
  persistReview: async (scanId, review) => {
    const { saveScanAiReview } = await import("../src/lib/audit/persist.server.ts");
    await saveScanAiReview(scanId, review);
  },
  repair: repairPocCode,
  runBackend: async (backendUrl, input) => {
    const poc = await runPocWithRpcRetries(backendUrl, {
      address: input.address,
      chainId: input.chainId,
      testCode: input.testCode,
      ...(input.tokenAddress ? { tokenAddress: input.tokenAddress } : {}),
    });
    return {
      status: poc.status,
      logs: poc.logs ?? "",
      durationMs: poc.durationMs ?? 0,
      executedSource: poc.executedSource,
    };
  },
  saveRun: async (record) => {
    const { saveFindingPocResult } = await import("../src/lib/audit/persist.server.ts");
    await saveFindingPocResult({
      findingId: record.findingId,
      scanId: record.scanId,
      status: record.status,
      source: record.source,
      output: record.output,
      durationMs: record.durationMs,
      chainId: record.chainId,
      targetAddress: record.targetAddress,
      exitCode: null,
      truncated: record.output.length > 50000,
    });
  },
  listRuns: async (findingId) => {
    const { listFindingPocRuns } = await import("../src/lib/audit/persist.server.ts");
    return listFindingPocRuns(findingId);
  },
  log: (line) => console.log(line),
};

export type AutoPocEntryInput = {
  /** The scan id the worker just persisted for this entry. */
  scanId: string;
  address: string;
  chainId: string;
  /** The saved report (severities as stored — see the header). */
  report: Report;
  /** The analyzed body (source, or bytecode for bytecode entries). */
  body: string;
};

export type AutoPocOptions = {
  backendUrl: string;
  /** Max chain attempts this run (0 = unlimited). */
  cap: number;
  /** The /start autoPoc flag — false makes every call a no-op. */
  enabled: boolean;
};

export type AutoPocEntryResult = {
  attempted: number;
  passed: number;
  failed: number;
  errors: number;
  skipped: number;
  /** Findings saved from an identical-code sibling's run (dedupe). */
  shared: number;
  /** Breaker state after this entry. */
  breakerTripped: boolean;
  /** One-line summary for the worker's per-entry log. */
  note: string;
};

const ZERO_ENTRY: Omit<AutoPocEntryResult, "breakerTripped" | "note"> = {
  attempted: 0,
  passed: 0,
  failed: 0,
  errors: 0,
  skipped: 0,
  shared: 0,
};

/**
 * An outcome is INFRA when the chain's verdict is "error" for a reason
 * that is not the PoC's fault: the backend never answered
 * (backend_unreachable), the fork/RPC layer failed (isRpcOrForkFailure
 * over the run output — compile errors are explicitly excluded there),
 * or the run dep itself threw (the chain's "Execution error:" catch).
 * A save failure is an error too, but it is a DATABASE problem, not
 * backend infra — it never counts toward the breaker.
 */
function isInfraOutcome(
  outcome: AdjudicationOutcome,
  lastRun: { status: string; logs: string } | null,
): boolean {
  if (outcome.verdict !== "error" || outcome.saveError) return false;
  if (lastRun?.status === "backend_unreachable") return true;
  if (outcome.output && isRpcOrForkFailure(outcome.output)) return true;
  if (outcome.output?.startsWith("Execution error:")) return true;
  return false;
}

/** Fold one chain outcome into the run tally + breaker state. */
function accountOutcome(
  state: AutoPocRunState,
  outcome: AdjudicationOutcome,
  lastRun: { status: string; logs: string } | null,
  delta: { passed: number; failed: number; errors: number; skipped: number },
): void {
  if (outcome.saveError) {
    delta.errors++;
    state.tally.errors++;
    state.consecutiveInfra = 0; // DB failure — not backend infra
    return;
  }
  switch (outcome.verdict) {
    case "passed":
      delta.passed++;
      state.tally.passed++;
      break;
    case "failed":
      delta.failed++;
      state.tally.failed++;
      break;
    case "error":
      delta.errors++;
      state.tally.errors++;
      break;
    default:
      // no_tests / skipped / unadapted (deliberate non-runs and
      // generation gaps) and no_poc (nothing runnable) all land in
      // the skipped bucket — none is a verdict and none is an error.
      delta.skipped++;
      state.tally.skipped++;
      break;
  }
  if (isInfraOutcome(outcome, lastRun)) {
    state.consecutiveInfra++;
    if (state.consecutiveInfra >= WORKER_AUTO_POC_BREAKER_THRESHOLD) {
      state.breakerTripped = true;
    }
  } else {
    state.consecutiveInfra = 0;
  }
}

/**
 * Run auto-PoC for one persisted entry's eligible findings, in report
 * order, sequentially. Mutates `state` (tally + breaker). Never
 * throws.
 */
export async function runAutoPocForEntry(
  state: AutoPocRunState,
  input: AutoPocEntryInput,
  opts: AutoPocOptions,
  deps: AutoPocDeps = defaultAutoPocDeps,
): Promise<AutoPocEntryResult> {
  const delta = { passed: 0, failed: 0, errors: 0, skipped: 0, shared: 0 };
  let attempted = 0;
  let processed = 0;
  const finish = (note: string): AutoPocEntryResult => ({
    ...ZERO_ENTRY,
    attempted,
    ...delta,
    breakerTripped: state.breakerTripped,
    note,
  });

  if (!opts.enabled) return finish("disabled");

  if (state.breakerTripped) {
    if (!state.breakerLogged) {
      state.breakerLogged = true;
      deps.log(
        "[worker] auto-poc disabled for the rest of this run: PoC backend unreachable (circuit breaker after " +
          `${WORKER_AUTO_POC_BREAKER_THRESHOLD} consecutive infra failures) — restart the backend and start a new run to re-enable`,
      );
    }
    return finish("circuit breaker open — skipped");
  }

  const candidates = selectAutoPocFindings(input.report, input.body);
  if (candidates.length === 0) return finish("no eligible high/critical findings");

  // Identical-draft dedupe for THIS entry: code hash -> the run that
  // already executed it. Scoped to the entry (one scan, one target,
  // one fork context) — across entries the stored-run layer (the
  // chain's digest reuse) is the dedupe of record.
  const runCache = new Map<string, SharedRun>();

  // Finding rows are keyed `${scanId}:${ord}` (bulk-persist) — the
  // chain keys dispositions, runs and saves on that database id.
  const dbFindings: Finding[] = input.report.findings.map((f, ord) => ({
    ...f,
    id: `${input.scanId}:${ord}`,
  }));
  const contractName = input.report.label || "Target";
  const pocToken = externalTokenCandidate(input.report, input.address);

  // The chain's AI review is scan-level: generate it at most once for
  // this entry (memoized across the entry's findings) and hand the
  // product to later findings as their existing review, exactly like
  // the app flow reuses a stored review. A generation failure is
  // memoized too — the chain marks its advisory step failed and the
  // PoC still runs.
  let reviewPromise: Promise<AiSecurityReview> | null = null;
  let review: AiSecurityReview | null = null;
  const ensureReview = (): Promise<AiSecurityReview> => {
    reviewPromise ??= deps
      .generateReview(
        contractName,
        input.body.slice(0, 30000),
        dbFindings.slice(0, 20),
        fourbyteForStoredReport(input.report),
      )
      .then((r) => {
        review = r;
        return r;
      });
    return reviewPromise;
  };

  for (const { ord } of candidates) {
    if (state.breakerTripped) break;
    if (autoPocCapReached(state, opts.cap)) {
      if (!state.capLogged) {
        state.capLogged = true;
        deps.log(
          `[worker] auto-poc per-run cap reached (${opts.cap}) — remaining flagged findings keep static-only records`,
        );
      }
      break;
    }
    const finding = dbFindings[ord]!;
    // Backend accounting for THIS finding, filled by the runPoc dep
    // below: the cap counts findings that sent new code to the
    // backend (realBackendCalls > 0); a finding served entirely from
    // the identical-code cache is a shared save instead.
    let realBackendCalls = 0;
    let sharedHits = 0;
    // The most recent backend interaction for THIS attempt — the
    // circuit breaker's infra evidence.
    let lastRun: { status: string; logs: string } | null = null;
    let outcome: AdjudicationOutcome | null = null;
    try {
      outcome = await deps.runChain(
        {
          scanId: input.scanId,
          finding,
          findings: dbFindings,
          contractName,
          body: input.body,
          targetAddress: input.address,
          chainId: input.chainId,
          aiReview: review,
          disposition: null,
          pocToken,
        },
        {
          requestAiReview: async () => ensureReview(),
          persistAiReview: async (r) => {
            await deps.persistReview(input.scanId, r);
          },
          listRuns: deps.listRuns,
          runPoc: async ({ address, chainId, testCode, tokenAddress }) => {
            // Identical-draft dedupe: the hash covers the exact code
            // that would be sent (post gate/repair), keyed with the
            // run's identity (target, chain, token) — constant within
            // an entry, spelled out so the invariant is explicit.
            const hash = autoPocCodeHash(testCode);
            const cacheKey = `${address}|${chainId ?? input.chainId}|${tokenAddress ?? ""}|${hash}`;
            const hit = runCache.get(cacheKey);
            if (hit) {
              sharedHits++;
              const shared: BackendRunResult = {
                status: hit.result.status,
                // The sharing is on the record: the chain saves this
                // output (under its own header) as the sibling's run
                // output, visibly distinct from an independent run,
                // while the sibling's finding row still gets the
                // verdict through the normal save.
                logs:
                  `[auto-poc] shared run — identical PoC code (SHA-256 ${hash}) was already executed ` +
                  `for finding ${hit.firstFindingId} in this entry; backend call skipped, this record ` +
                  `shares that run's verdict.\n${hit.result.logs}`,
                // This finding spent no backend time of its own.
                durationMs: 0,
                executedSource: hit.result.executedSource,
              };
              lastRun = { status: shared.status, logs: shared.logs };
              return shared;
            }
            const r = await deps.runBackend(opts.backendUrl, {
              address,
              chainId: chainId ?? input.chainId,
              testCode,
              ...(tokenAddress ? { tokenAddress } : {}),
            });
            realBackendCalls++;
            if (isShareableRunResult(r)) {
              runCache.set(cacheKey, {
                result: {
                  status: r.status,
                  logs: r.logs,
                  durationMs: r.durationMs,
                  executedSource: r.executedSource,
                },
                firstFindingId: finding.id,
              });
            }
            lastRun = { status: r.status, logs: r.logs };
            return r;
          },
          repairPoc: async ({ contractName: name, originalCode, errorLogs, body }) => {
            try {
              const repaired = await deps.repair(name, originalCode, errorLogs, body);
              return repaired?.fixedCode ?? "";
            } catch {
              // No key / LLM down: the chain treats an empty repair as
              // "generation produced nothing" and saves honestly.
              return "";
            }
          },
          isCompileError: (logs) => isPocCompileError(logs),
          saveRun: deps.saveRun,
        },
      );
    } catch (err) {
      // The chain is not supposed to throw (its deps are the throwing
      // kind, and it catches them) — but auto-PoC must never fail the
      // pipeline entry, so an escape lands here as a plain error.
      delta.errors++;
      state.tally.errors++;
      state.consecutiveInfra = 0;
      deps.log(
        `[worker] auto-poc ${input.address} ${finding.detector}: error (chain threw: ${err instanceof Error ? err.message : String(err)})`,
      );
    }
    processed++;
    // Cap accounting (see the header): only a finding that actually
    // sent new code to the backend consumes an attempt — a shared
    // save is free, and a chain that never reached the backend (the
    // gate / unadapted saves) consumed no backend budget either.
    if (realBackendCalls > 0) {
      attempted++;
      state.tally.attempted++;
    }
    if (outcome) {
      accountOutcome(state, outcome, lastRun, delta);
      const sharedSave =
        realBackendCalls === 0 &&
        sharedHits > 0 &&
        outcome.runStep === "executed" &&
        !outcome.saveError;
      if (sharedSave) {
        delta.shared++;
        state.tally.shared++;
      }
      const savedStatus = outcome.saveError
        ? `error (save failed: ${outcome.saveError})`
        : (outcome.verdict ?? outcome.kind);
      deps.log(
        `[worker] auto-poc ${input.address} ${finding.detector}: ${savedStatus}${sharedSave ? " (shared run)" : ""}`,
      );
    }
  }

  const note =
    processed === 0
      ? "cap reached — skipped"
      : `${attempted} attempted: ${delta.passed} passed, ${delta.failed} failed, ${delta.errors} error(s), ${delta.skipped} skipped` +
        (delta.shared > 0 ? `, ${delta.shared} shared` : "") +
        (state.breakerTripped ? " — circuit breaker tripped" : "");
  return finish(note);
}
