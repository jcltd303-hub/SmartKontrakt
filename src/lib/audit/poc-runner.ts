// src/lib/audit/poc-runner.ts
//
// One entry point for "run the PoC for this finding".
//
// WHY THIS EXISTS
//
// The adjudication chain (adjudicate-chain.ts) already owns the sequence — persist,
// review, PoC, verdict, suggestion — and takes the PoC runner as an injected callback.
// That part is right. What had drifted is the WIRING: five components each built the same
// runner input by hand, and foundry-backend.ts exports three names for effectively one
// function:
//
//   runPocWithRpcRetries = runSmartPoc                    (line 479, a bare alias)
//   runPocOnBackend(...)  = runSmartPoc(..., retry:false) (line 481)
//
// use-workbench-controller.ts (2,220 lines) touches all three. interactive-audit.tsx
// imports two of them and uses them interchangeably. Two names for one function is how the
// call sites drifted apart in the first place.
//
// This module does not replace those exports — it sits in front of them so a caller passes
// a finding and a target instead of assembling testCode, rpc and retry flags itself.
//
// WHAT IS DELIBERATELY NOT HERE
//
// No persistence, no AI review, no verdict. Those belong to adjudicate-chain.ts, which
// already owns them. This is only: which code, should we run, run it, hand back the result.

import { needsSmartPoc, runSmartPoc } from "./foundry-backend";

/** The minimum a finding must carry to be runnable. Matches what needsSmartPoc reads. */
export type PocFinding = {
  severity?: string;
  exploitSolidity?: string;
  pocCode?: string | null;
  pocStatus?: string | null;
  pocRunAt?: string | null;
  pocOutput?: string | null;
};

export type PocTarget = {
  address: string;
  chainId: string | number;
  /** Optional ERC-20 the harness should judge (template 46's POC_TOKEN). */
  tokenAddress?: string;
};

export type RunPocOptions = {
  backendUrl: string;
  finding: PocFinding;
  target: PocTarget;
  /**
   * Run even when a previous verdict exists. The workbench passes this when the user
   * clicks adjudicate again; the worker never does.
   */
  force?: boolean;
  /** Only these severities are worth a fork run. Defaults to critical + high. */
  severities?: readonly string[];
  /** Retry across RPC candidates. Off for a one-shot manual run. */
  retry?: boolean;
  /** Called when a retry moves to the next endpoint, for progress UI. */
  onRetry?: (info: { attempt: number; total: number; url?: string; reason?: string }) => void;
};

const DEFAULT_SEVERITIES = ["critical", "high"] as const;

/**
 * Which Solidity to run.
 *
 * pocCode wins over exploitSolidity: pocCode is what was actually executed last time, so
 * re-running it is reproducible. exploitSolidity is the model's fresh output and is only
 * used when nothing has been executed yet.
 *
 * Returns null when there is nothing to run, so callers never send an empty body to the
 * backend and receive a "skipped" that looks like a verdict.
 */
export function pocTestCode(finding: PocFinding): string | null {
  const code = (finding.pocCode ?? "").trim() || (finding.exploitSolidity ?? "").trim();
  return code.length > 0 ? code : null;
}

/**
 * Should this finding be run at all?
 *
 * Severity gate first — a medium is not worth a fork — then needsSmartPoc, which is the
 * existing "has this exact code already been run and produced a real verdict" check.
 * `force` bypasses only the second gate: it re-runs a finding that already has a verdict,
 * it does not promote a medium to critical.
 */
export function shouldRunPoc(
  finding: PocFinding,
  opts: { force?: boolean; severities?: readonly string[] } = {},
): boolean {
  const severities = opts.severities ?? DEFAULT_SEVERITIES;
  if (finding.severity && !severities.includes(finding.severity)) return false;
  if (!pocTestCode(finding)) return false;
  if (opts.force) return true;
  return needsSmartPoc(finding);
}

/**
 * Run the PoC for one finding, or return null when it should not run.
 *
 * null means "declined, for a reason shouldRunPoc already expressed" — it is not a verdict
 * and callers must not record it as one. Every path that actually reaches the backend
 * returns a real result object, including the skip and error statuses the backend itself
 * produces, because those carry a logs field that explains why.
 */
export async function runPocForFinding(
  opts: RunPocOptions,
): Promise<Awaited<ReturnType<typeof runSmartPoc>> | null> {
  const { backendUrl, finding, target } = opts;

  if (!shouldRunPoc(finding, { force: opts.force, severities: opts.severities })) return null;

  const testCode = pocTestCode(finding);
  if (!testCode) return null;

  // No rpcList passed on purpose. runSmartPoc already does
  //   input.rpcList?.length ? input.rpcList : rpcCandidates(input.chainId)
  // so omitting it means the endpoint list comes from RPC_URLS in one place, rather than
  // each caller resolving its own and drifting when the env changes.
  return runSmartPoc(backendUrl, {
    address: target.address.trim(),
    testCode,
    chainId: String(target.chainId),
    ...(target.tokenAddress ? { tokenAddress: target.tokenAddress } : {}),
    retry: opts.retry ?? true,
    ...(opts.onRetry ? { onRetry: opts.onRetry } : {}),
  } as Parameters<typeof runSmartPoc>[1]);
}
