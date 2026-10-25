/**
 * ResNet1D screening — the shared result shape and its risk-score term.
 *
 * ResNet1D (see ml/image-vuln/RESNET1D.md) is a five-class multi-label
 * classifier trained on 16,384-byte prefixes. Current audits evaluate all bytes
 * in consecutive zero-padded, L2-normalized windows and class-max pool. The
 * prefix benchmark does not evaluate that pooling policy. It is a SCREENING signal — Slither-pseudo-labelled training
 * data, test micro F1 ≈ 0.74 — not a detector. Its classes deliberately use
 * the same names as the model's manifest (`CLASSES` in
 * src/lib/image-ml/runtime.ts; a test pins the two lists together).
 *
 * Where a result comes from depends on the environment, by design:
 *   - the pipeline worker (Node) runs the ONNX model itself
 *     (src/lib/image-ml/resnet-node.server.ts) for every address entry;
 *   - the browser audit flows (batch pipeline, single-address fetch) run
 *     the same model in the existing ONNX Web Worker
 *     (src/lib/image-ml/run-resnet-browser.ts);
 *   - the workbench save path (persist.server runAndStore) runs the Node
 *     runner for pasted-bytecode audits.
 * All three produce THIS shape, attach it to the Report in analyzeAddress /
 * runAndStore via attachResnetToReport, and persist it in
 * contract_scans.resnet_json (migration 0018).
 *
 * Scoring discipline (the calibration rules in severity-calibration.ts are
 * about FINDINGS and are untouched by this module):
 *   - ResNet never changes a finding's severity, confidence or detector.
 *   - ResNet never creates a score on its own: riskScore() consults the
 *     term only when static analysis produced a finding above info —
 *     a findings-free (or info-only) report is untouched by it.
 *   - With findings present, ResNet adds a bounded pressure term
 *     (MAX_RESNET_BONUS), in the same family as the volume and
 *     confirmed-exploit terms: it can push a report's score up by at most
 *     that many points, and only when the model flags at least one class
 *     at or above that class's own validation-selected threshold.
 */

export const RESNET_CLASSES = [
  "access-control",
  "arithmetic",
  "reentrancy",
  "unchecked-calls",
  "others",
] as const;

export type ResnetClass = (typeof RESNET_CLASSES)[number];

export type ResnetPrediction = {
  label: string;
  /** Sigmoid probability 0..1 from the model. */
  score: number;
  /** The class's validation-selected decision threshold (from the manifest). */
  threshold: number;
  /** score >= threshold — the model's own flag, not a SmartKontrakt verdict. */
  flagged: boolean;
};

export type ResnetResult = {
  /** Present on full-byte audits; absent on historical prefix-only rows. */
  processedBytes?: number;
  windows?: number;
  policy?: string;
  modelId: string;
  architecture: string;
  checkpointSha256: string;
  predictions: ResnetPrediction[];
  /** Total supplied runtime length; processedBytes identifies current all-byte coverage. */
  inputBytes: number;
  /** Historical prefix-only rows may be truncated. Current full-byte runs set false. */
  truncated: boolean;
  /** ISO timestamp of the inference run. */
  ranAt: string;
};

/** Hard cap on the risk-score term, whatever the model says. */
export const MAX_RESNET_BONUS = 6;

/** Classes the model flagged at/above their own thresholds. */
export function resnetFlagged(result: ResnetResult | null | undefined): ResnetPrediction[] {
  if (!result) return [];
  return result.predictions.filter((p) => p.flagged);
}

/**
 * The bounded score term:
 *   - no flagged class → 0 (a quiet model changes nothing);
 *   - the strongest flagged class → +3, plus +1 when it clears its
 *     threshold by ≥ 0.25 (a decisive flag, not a borderline one);
 *   - each additional flagged class → +1;
 *   - total capped at MAX_RESNET_BONUS.
 */
export function resnetRiskBonus(result: ResnetResult | null | undefined): number {
  const flagged = resnetFlagged(result);
  if (flagged.length === 0) return 0;
  const strongestMargin = Math.max(...flagged.map((p) => p.score - p.threshold));
  const bonus = 3 + (strongestMargin >= 0.25 ? 1 : 0) + (flagged.length - 1);
  return Math.min(MAX_RESNET_BONUS, bonus);
}

/**
 * Which detector families a ResNet class corresponds to — used ONLY to
 * write the human-readable evidence note (which static detectors the ML
 * signal agrees/disagrees with). Never used for scoring or selection.
 */
export const RESNET_CLASS_DETECTORS: Record<string, string[]> = {
  reentrancy: ["reentrancy", "read-only-reentrancy", "bytecode-reentrancy-shape"],
  "unchecked-calls": ["unchecked-call", "erc20-unchecked", "bytecode-unchecked-call"],
  "access-control": [
    "unprotected-admin",
    "unprotected-ether",
    "unprotected-initializer",
    "centralization",
    "delegatecall",
    "token-drain",
  ],
  arithmetic: ["div-before-mul", "msg-value-loop"],
  others: [],
};

/**
 * One-line inventory note recording that the screening ran and what it
 * did. `appliedBonus` is the score delta the attach actually applied
 * (riskScore after minus before) — the note must report THAT, not the
 * theoretical term: on a findings-free report the term is computed but
 * the findings-free guard keeps the score at 0, and the note says so.
 */
export function resnetSummaryLine(result: ResnetResult, appliedBonus: number): string {
  const flagged = resnetFlagged(result);
  const scope =
    `over ${result.inputBytes} runtime bytes${result.truncated ? " (prefix only)" : ""}${result.windows ? ` in ${result.windows} consecutive windows (experimental class-max pooling)` : ""}`;
  if (flagged.length === 0) {
    return (
      `ResNet1D screening (${result.modelId}): no vulnerability class at or above its threshold ` +
      `${scope} — risk score unchanged.`
    );
  }
  const parts = flagged.map((p) => `${p.label} ${p.score.toFixed(2)} (threshold ${p.threshold.toFixed(2)})`);
  if (appliedBonus <= 0) {
    return (
      `ResNet1D screening (${result.modelId}): flagged ${parts.join(", ")} ${scope} — ` +
        `recorded as evidence only: with no static finding above info, the ML signal does not move the risk score.`
    );
  }
  return (
    `ResNet1D screening (${result.modelId}): flagged ${parts.join(", ")} ${scope} — ` +
      `ML signal folded into the risk score (+${appliedBonus}). Screening only: no finding was created or re-scored by the model.`
  );
}

export function serializeResnet(result: ResnetResult | null | undefined): string | null {
  return result ? JSON.stringify(result) : null;
}

const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

/**
 * Fail-soft reader for contract_scans.resnet_json: anything malformed —
 * a pre-0018 row, a hand-edited value, a future shape — reads as "not run"
 * (null) rather than breaking the record. Mirrors the archive's other
 * advisory-JSON readers.
 */
export function parseResnetJson(text: string | null | undefined): ResnetResult | null {
  if (!text) return null;
  try {
    const v = JSON.parse(text) as Record<string, unknown>;
    if (!v || typeof v !== "object" || Array.isArray(v)) return null;
    if (typeof v.modelId !== "string" || !v.modelId) return null;
    if (typeof v.architecture !== "string" || !v.architecture) return null;
    if (typeof v.checkpointSha256 !== "string" || !/^[a-f0-9]{64}$/.test(v.checkpointSha256)) return null;
    if (!Array.isArray(v.predictions) || v.predictions.length !== RESNET_CLASSES.length) return null;
    const predictions: ResnetPrediction[] = [];
    for (const [i, raw] of v.predictions.entries()) {
      const p = raw as Record<string, unknown>;
      if (!p || typeof p !== "object") return null;
      const label = p.label;
      if (typeof label !== "string" || label !== RESNET_CLASSES[i]) return null;
      if (!isNum(p.score) || p.score < 0 || p.score > 1) return null;
      if (!isNum(p.threshold) || p.threshold < 0 || p.threshold > 1) return null;
      if (typeof p.flagged !== "boolean" || p.flagged !== (p.score >= p.threshold)) return null;
      predictions.push({
        label,
        score: p.score,
        threshold: p.threshold,
        flagged: p.flagged,
      });
    }
    if (!Number.isSafeInteger(v.inputBytes) || (v.inputBytes as number) < 1) return null;
    if (typeof v.truncated !== "boolean") return null;
    if (typeof v.ranAt !== "string" || !v.ranAt) return null;
    const coverage = v.processedBytes !== undefined || v.windows !== undefined || v.policy !== undefined;
    if (coverage && (v.policy !== "consecutive-16384-zero-pad-l2-class-max-v1" ||
      !Number.isSafeInteger(v.processedBytes) || v.processedBytes !== v.inputBytes ||
      !Number.isSafeInteger(v.windows) || v.windows !== Math.ceil((v.inputBytes as number)/16384) ||
      v.truncated !== false)) return null;
    return {
      modelId: v.modelId,
      architecture: v.architecture,
      checkpointSha256: v.checkpointSha256,
      predictions,
      inputBytes: v.inputBytes as number,
      truncated: v.truncated,
      ranAt: v.ranAt,
      ...(coverage ? {processedBytes:v.processedBytes as number,windows:v.windows as number,policy:v.policy as string} : {}),
    };
  } catch {
    return null;
  }
}
