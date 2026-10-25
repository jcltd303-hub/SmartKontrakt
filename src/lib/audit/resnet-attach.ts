/**
 * attachResnetToReport — the one place a ResNet1D result lands on a Report.
 *
 * Called by analyzeAddress (both fetch paths) when the caller injects a
 * runner, and by runAndStore for pasted-bytecode saves. Keeping the
 * mutation here means every entry point gets identical behaviour:
 *   - the result is stored on report.resnet (persisted as resnet_json);
 *   - report.riskScore is recomputed WITH the result, so the stored
 *     score and the displayed score are the resnet-aware one — the
 *     detectors' own scores are the baseline (riskScore(findings));
 *   - exactly one inventory note records that the screening ran, what
 *     it flagged and what it did to the score (resnetSummaryLine) —
 *     the audit trail Jer reads in the workbench and the archive.
 *
 * Fail-soft: no code to classify, a runner that returns null, or a
 * runner that throws all leave the report exactly as the static
 * analysis produced it. ResNet is a screening layer; the audit must
 * never fail because the model did.
 */
import { riskScore } from "./risk.ts";
import { resnetSummaryLine, type ResnetResult } from "./resnet-result.ts";
import type { Report } from "./types.ts";

/** A runner screens runtime bytecode (hex, 0x optional) or returns null. */
export type ResnetRunner = (bytecode: string) => Promise<ResnetResult | null>;

const HEX_BODY = /^(0x)?[0-9a-fA-F]+$/;

/**
 * The runtime code a report's screening should consume, if any:
 *   - verified/source path: report.runtimeBytecode, bound to the source
 *     by analyzeAddress (the source body itself is NOT bytecode);
 *   - bytecode path: the fetched/pasted bytecode body itself.
 * Pasted SOURCE has no runtime code — null, screening not applicable,
 * which is the honest state (nothing deployed to classify).
 */
export function runtimeCodeForReport(report: Report, body?: string | null): string | null {
  if (report.runtimeBytecode?.code) return report.runtimeBytecode.code;
  if (report.inputKind === "bytecode" && body && HEX_BODY.test(body.trim())) return body;
  return null;
}

/**
 * Run the injected runner over `code` and fold the result into the
 * report. Returns true when a result was attached.
 */
export async function attachResnetToReport(
  report: Report,
  code: string | null | undefined,
  runner: ResnetRunner,
): Promise<boolean> {
  if (!code) return false;
  let result: ResnetResult | null;
  try {
    result = await runner(code);
  } catch {
    return false;
  }
  if (!result) return false;
  report.resnet = result;
  const before = report.riskScore;
  report.riskScore = riskScore(report.findings, result);
  const applied = report.riskScore - before;
  report.inventory.notes = [...report.inventory.notes, resnetSummaryLine(result, applied)];
  return true;
}
