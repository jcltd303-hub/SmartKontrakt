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
 * runner that throws preserve static findings and record missing evidence,
 * clearing any previous model result/bonus. ResNet is a screening layer; the audit must
 * never fail because the model did.
 */
import { riskScore } from "./risk.ts";
import { resnetSummaryLine, parseResnetJson, type ResnetResult } from "./resnet-result.ts";
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
  const unavailable = (status: "error"|"unavailable", error:string):false => {
    report.resnet = null;
    report.riskScore = riskScore(report.findings);
    report.inventory.resnetStatus = {status,error};
    report.inventory.notes = report.inventory.notes.filter(note=>!note.startsWith("ResNet1D screening"));
    report.inventory.notes.push(`ResNet1D screening unavailable: ${error} Missing evidence is not a negative prediction.`);
    return false;
  };
  if (!code) return unavailable("unavailable","No deployed runtime bytecode available.");
  let result: ResnetResult | null;
  try { result = await runner(code); }
  catch { return unavailable("error","Inference failed."); }
  if (!result) return unavailable("unavailable","The model could not evaluate the runtime.");
  const checked = parseResnetJson(JSON.stringify(result));
  if (!checked || checked.inputBytes !== code.trim().replace(/^0x/i,"").length/2)
    return unavailable("error","Invalid model result or runtime coverage.");
  report.resnet = checked;
  report.inventory.resnetStatus = {status:"ok"};
  const baseline = riskScore(report.findings);
  report.riskScore = riskScore(report.findings, checked);
  report.inventory.notes = report.inventory.notes.filter(note=>!note.startsWith("ResNet1D screening"));
  report.inventory.notes.push(resnetSummaryLine(checked,report.riskScore-baseline));
  return true;
}
