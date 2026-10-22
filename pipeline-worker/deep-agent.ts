/**
 * Deep Agent for the pipeline worker — the same propose -> fork-PoC ->
 * reward -> deeper loop as the workbench AI tab (see
 * src/lib/audit/deep-agent.server.ts), but running headless per flagged
 * address in the 43k-address run.
 *
 * Differences from the workbench path:
 * - Gated: only runs for flagged addresses (see isDeepAgentFlagged) AND
 *   only for source analyses (bytecode-only items have no source for the
 *   model to propose hypotheses from).
 * - PoCs run against the local Foundry backend (:8787) via the shared
 *   runPocOnBackend helper — same mapping as the workbench, so a 409
 *   "busy" (Jer tapped Run PoC manually) is retried, not treated as a
 *   verdict.
 * - Confirmed hypotheses become Findings on the report (fork-proven, so
 *   confidence high) and persist through writeAuditBatch like any other
 *   finding. Refuted hypotheses are NOT persisted — they only steer the
 *   next round.
 * - Never throws: any failure (no key, LLM error, backend down) stops
 *   this address's agent loop and leaves the static-only record intact.
 *   The caller decides what a backend outage means for the run (circuit
 *   breaker lives in worker.ts).
 *
 * Bounds (same as the workbench): at most 3 rounds, at most 2
 * hypotheses per round. The per-run item cap lives in worker.ts
 * (deepAgentMaxItems) — this module runs one address.
 */

import type { Finding, PocResult, Report, Severity } from "../src/lib/audit/types.ts";
import type {
  DeepAgentHypothesis,
  DeepAgentPriorResult,
} from "../src/lib/audit/deep-agent.server.ts";
import { runDeepAgentRound } from "../src/lib/audit/deep-agent.server.ts";
// runPocOnBackend is the shared helper also used by the workbench. It
// never touches localStorage here: the backend URL is passed explicitly,
// and the helper only reads localStorage inside getBackendUrl(), which
// this module never calls.
import { runPocWithRpcRetries } from "../src/lib/audit/foundry-backend.ts";
import { type FourbyteResults } from "../src/lib/audit/fourbyte.ts";
// SmartPoC pipeline (arXiv:2511.12993): the GRE-Engine (generate-repair-execute)
// and Action-State Differential Verification replace the old single-repair step.
import {
  runGreRepairLoop,
  runDifferentialVerification,
  type PocExecution,
} from "../src/lib/audit/smartpoc/engine.server.ts";
import { pocTargetFromSource } from "../src/lib/audit/smartpoc/bce.ts";

export const WORKER_DEEP_AGENT_MAX_ROUNDS = 3;
export const WORKER_DEEP_AGENT_DEFAULT_BACKEND_URL = "http://127.0.0.1:8787";
export const WORKER_DEEP_AGENT_DEFAULT_MAX_ITEMS = 250;
export const WORKER_DEEP_AGENT_DEFAULT_MIN_SEVERITY: Severity = "high";
/** SmartPoC GRE-Engine retry budget (paper §4.2: B = 5). */
export const WORKER_DEEP_AGENT_RETRY_BUDGET = 5;

const SEV_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

// Risk weights — must match scoreOf() in src/lib/audit/engine.ts.
const RISK_WEIGHT: Record<Severity, number> = {
  critical: 28,
  high: 14,
  medium: 6,
  low: 2,
  info: 0,
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export type WorkerDeepAgentOptions = {
  /** Foundry backend base URL (no trailing slash needed). */
  backendUrl: string;
  /** Max LLM rounds for one address. */
  maxRounds: number;
  /** Gate: flagged = >= 1 finding at or above this severity. */
  minSeverity: Severity;
  /** GRE-Engine retry budget (default WORKER_DEEP_AGENT_RETRY_BUDGET). */
  retryBudget?: number;
  /**
   * Run SmartPoC Differential Verification on a passing PoC before it becomes
   * a finding (default true). Costs 3 extra LLM calls per confirmed PoC.
   */
  verify?: boolean;
};

/** Per-address Deep Agent outcome. `ran` is false when the loop was skipped. */
export type WorkerDeepAgentResult = {
  ran: boolean;
  skipReason: string | null;
  rounds: number;
  confirmed: Finding[];
  refuted: number;
  errors: number;
  /** True when the PoC backend was unreachable (caller: circuit-break). */
  backendDown: boolean;
  /** One-line summary, appended to report.inventory.notes by the caller. */
  note: string;
};

/**
 * "Flagged" = static analysis found at least one finding at or above
 * minSeverity. Those are the contracts worth spending LLM + PoC budget
 * on; everything else keeps its static-only record.
 */
export function isDeepAgentFlagged(report: Report, minSeverity: Severity): boolean {
  const min = SEV_RANK[minSeverity] ?? SEV_RANK.high;
  return report.findings.some((f) => (SEV_RANK[f.severity] ?? 0) >= min);
}

/** A fork-confirmed hypothesis becomes a first-class finding. */
function confirmedFinding(h: DeepAgentHypothesis, round: number, index: number, poc: PocResult): Finding {
  return {
    id: `deep-r${round}-${index}`,
    severity: h.severity,
    swc: null,
    title: h.title,
    confidence: "high",
    detector: h.detector,
    summary: `Deep Agent confirmed on fork (round ${round}): ${h.hypothesis}`,
    walkthrough: [
      `PoC passed on a live-net fork via the Foundry backend (${poc.durationMs}ms).`,
      "PoC output:",
      poc.logs.slice(0, 3000),
    ].join("\n"),
    exploitSolidity: h.foundryTestCode,
    pocStatus: poc.status, pocOutput: poc.logs, pocCode: h.foundryTestCode,
    pocDurationMs: poc.durationMs, pocRunAt: poc.runAt,
    remediationSolidity: "",
    locationFn: null,
    locationLine: null,
    snippet: "",
  };
}

/**
 * Append confirmed findings to a report and recompute the risk score +
 * summary in engine.ts's format, so the persisted record reflects the
 * agent's findings. Also appends the agent note to inventory.notes.
 */
export function applyConfirmedFindings(report: Report, confirmed: Finding[], note: string): void {
  if (confirmed.length === 0 && !note) return;
  report.findings.push(...confirmed);
  const raw = report.findings.reduce((sum, f) => sum + (RISK_WEIGHT[f.severity] ?? 0), 0);
  report.riskScore = Math.min(100, raw);
  const crit = report.findings.filter((f) => f.severity === "critical").length;
  const high = report.findings.filter((f) => f.severity === "high").length;
  const top = report.findings[0];
  report.summary = `${report.label}: ${report.findings.length} findings, ${crit} critical, ${high} high. Lead issue: ${top?.title ?? "—"}.`;
  if (note) report.inventory.notes.push(note);
}

/** Adapter: run a PoC on the backend and normalize it to a `PocExecution`. */
async function runPocAsExecution(
  backendUrl: string,
  address: string,
  testCode: string,
  chainId = "ethereum",
): Promise<PocExecution> {
  const r = await runPocOnce(backendUrl, address, testCode, chainId);
  return {
    status: r.status,
    logs: r.logs ?? "",
    durationMs: r.durationMs ?? 0,
    runAt: r.runAt ?? new Date().toISOString(),
    error: r.error,
  };
}

/** One PoC run, retrying only while the backend reports busy (409). */
async function runPocOnce(
  backendUrl: string,
  address: string,
  testCode: string,
  chainId = "ethereum",
): Promise<PocResult> {
  let last: PocResult | null = null;
  for (let attempt = 0; attempt < 5; attempt++) {
    const poc = await runPocWithRpcRetries(backendUrl, { address, testCode, chainId });
    last = poc;
    if (poc.status === "error" && /409|busy/i.test(`${poc.error ?? ""} ${poc.logs ?? ""}`)) {
      await sleep(30_000);
      continue;
    }
    return poc;
  }
  return last!;
}

/**
 * Run the Deep Agent loop for one flagged address. Never throws.
 */
export async function runWorkerDeepAgent(
  input: { address: string; contractName: string; body: string; findings: Finding[]; inputKind: string; chainId?: string; fourbyte?: FourbyteResults },
  opts: WorkerDeepAgentOptions,
): Promise<WorkerDeepAgentResult> {
  const base: Omit<WorkerDeepAgentResult, "note"> = {
    ran: false,
    skipReason: null,
    rounds: 0,
    confirmed: [],
    refuted: 0,
    errors: 0,
    backendDown: false,
  };
  if (input.inputKind !== "source") {
    return { ...base, skipReason: "bytecode-only, no source for hypotheses", note: "" };
  }
  // The prompt's findings grow with confirmed hypotheses, so later rounds
  // go deeper on proven surfaces (same as the workbench loop).
  const findingsForPrompt: Finding[] = [...input.findings];
  const priorResults: DeepAgentPriorResult[] = [];
  let stopped: string | null = null;
  let totalLlmMs = 0;
  let repairsAttempted = 0;
  let repairsSucceeded = 0;
  // PoCs the pre-run balance guard skipped (target holds 0 native value).
  let balanceSkips = 0;
  // SmartPoC sanitizer target (contract name + function signatures) derived
  // from the source, so the GRE-Engine can align the pragma and strip any
  // re-declaration of the target's own functions.
  const target = pocTargetFromSource(input.body, input.contractName);

  try {
    for (let round = 1; round <= opts.maxRounds; round += 1) {
      base.rounds = round;
      let hypotheses: DeepAgentHypothesis[];
      let stopReason: string | null;
      try {
        const res = await runDeepAgentRound(
          input.contractName,
          input.body,
          findingsForPrompt,
          priorResults,
          round,
          input.fourbyte,
        );
        hypotheses = res.hypotheses;
        stopReason = res.stopReason;
        totalLlmMs += res.llmMs ?? 0;
      } catch (err) {
        base.errors += 1;
        stopped = `LLM round failed: ${err instanceof Error ? err.message : String(err)}`;
        break;
      }
      if (hypotheses.length === 0) {
        stopped = stopReason ?? "no new hypotheses";
        break;
      }
      let stopRound = false;
      for (let i = 0; i < hypotheses.length; i += 1) {
        const h = hypotheses[i]!;
        // SmartPoC GRE-Engine (§3.3): sanitize the draft (pragma/import align,
        // strip any re-declaration of the target's own functions), execute it,
        // and repair with compiler/runtime feedback up to the retry budget.
        // This replaces the previous single-repair step.
        repairsAttempted += 1;
        const gre = await runGreRepairLoop(
          { draft: h.foundryTestCode, target },
          (code) => runPocAsExecution(opts.backendUrl, input.address, code, input.chainId),
          opts.retryBudget ?? WORKER_DEEP_AGENT_RETRY_BUDGET,
        );
        const testCode = gre.code;
        const poc: PocResult = gre.execution ?? {
          status: "error",
          logs: gre.stopReason ?? "no execution",
          durationMs: 0,
          runAt: new Date().toISOString(),
        };
        if (gre.ok) repairsSucceeded += 1;

        if (poc.status === "passed") {
          // SmartPoC Differential Verification (§3.4): confirm the finding with
          // an action-state oracle before it is promoted to a finding. The DV
          // verdict is the oracle; a NOTVALIDATED result is a refutation.
          let validated = true;
          let dvNote = "";
          if (opts.verify !== false) {
            try {
              const dv = await runDifferentialVerification(
                {
                  finding: {
                    title: h.title, severity: h.severity, detector: h.detector,
                    summary: h.hypothesis, locationFn: null,
                  },
                  poc: testCode,
                  publicAbis: [],
                },
                (code) => runPocAsExecution(opts.backendUrl, input.address, code, input.chainId),
              );
              validated = dv.validated;
              dvNote = `\nSmartPoC DV: ${dv.validated ? "VALIDATED" : "NOTVALIDATED"} — ${dv.reason}`;
            } catch (dvErr) {
              dvNote = `\nSmartPoC DV error: ${dvErr instanceof Error ? dvErr.message : String(dvErr)}`;
            }
          }
          if (validated) {
            const finding = confirmedFinding({ ...h, foundryTestCode: testCode }, round, i, poc);
            finding.walkthrough += dvNote;
            base.confirmed.push(finding);
            findingsForPrompt.push(finding);
            priorResults.push({ title: h.title, detector: h.detector, outcome: "confirmed", pocLogs: poc.logs.slice(0, 1500) });
          } else {
            base.refuted += 1;
            priorResults.push({ title: h.title, detector: h.detector, outcome: "refuted", pocLogs: `${poc.logs.slice(0, 1200)}${dvNote}` });
          }
        } else if (poc.status === "failed") {
          base.refuted += 1;
          priorResults.push({ title: h.title, detector: h.detector, outcome: "refuted", pocLogs: poc.logs.slice(0, 1500) });
        } else if (poc.status === "skipped") {
          // Pre-run balance guard: the target holds 0 native value, so there is
          // nothing at stake to exploit. Not a verdict and not an error — skip
          // this hypothesis and keep going.
          balanceSkips += 1;
        } else if (poc.status === "backend_unreachable") {
          base.errors += 1;
          base.backendDown = true;
          stopped = "PoC backend unreachable";
          stopRound = true;
          break;
        } else {
          // error: infra, not a verdict — stop the loop.
          base.errors += 1;
          stopped = `PoC run failed (${poc.status})`;
          stopRound = true;
          break;
        }
      }
      if (stopRound) break;
      if (round === opts.maxRounds) stopped = "max rounds reached";
    }
  } catch (err) {
    // Defensive: the loop must never throw into the run loop.
    base.errors += 1;
    stopped = `unexpected: ${err instanceof Error ? err.message : String(err)}`;
  }

  const note = `Deep Agent: ${base.rounds} round(s), ${base.confirmed.length} confirmed on fork, ${base.refuted} refuted${balanceSkips > 0 ? `, ${balanceSkips} skipped (0 balance)` : ""}${base.errors > 0 ? `, ${base.errors} error(s)` : ""}, LLM ${(totalLlmMs / 1000).toFixed(1)}s${repairsAttempted > 0 ? `, repair ${repairsSucceeded}/${repairsAttempted}` : ""}${stopped ? ` — ${stopped}` : ""}`;
  return { ...base, ran: true, note };
}

