type Fields = Record<string, unknown>;
const fields = (value: unknown): Fields =>
  value && typeof value === "object" && !Array.isArray(value) ? (value as Fields) : {};
const metric = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1 ? value : null;
const count = (value: unknown): number | null =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
const epoch = (value: unknown): number | null =>
  (count(value) ?? 0) > 0 ? (value as number) : null;
const pair = (value: unknown) => ({
  micro: metric(fields(value).microF1),
  macro: metric(fields(value).macroF1),
});

export function evaluationSummary(training: unknown, evaluation: unknown) {
  const train = fields(training),
    measured = fields(evaluation);
  const samples = fields(train.samples ?? train.counts);
  const validation = fields(measured.validation);
  const selectedEpoch = epoch(train.selectedEpoch);
  const history = Array.isArray(train.history) ? train.history : [];
  const selectedHistory = fields(
    history.find((row) => selectedEpoch !== null && fields(row).epoch === selectedEpoch),
  );
  const validationPair = pair(validation.validation ?? validation);
  return {
    counts: {
      train: count(samples.train),
      validation: count(samples.validation),
      test: count(samples.test),
    },
    selectedEpoch,
    epochs: epoch(train.epochs),
    validation: {
      micro: validationPair.micro,
      macro: validationPair.macro ?? metric(selectedHistory.validationMacroF1),
    },
    test: pair(measured.test ?? measured),
  };
}

export function inputCoverage(bytes: number) {
  if (!Number.isSafeInteger(bytes) || bytes < 1)
    throw new Error("Coverage needs a positive byte count.");
  const used = Math.min(bytes, 16384);
  return { used, omitted: bytes - used, total: bytes, fraction: used / bytes };
}

export type WindowComparison = {
  prefix: { validation: ReturnType<typeof pair>; test: ReturnType<typeof pair> };
  windows: { validation: ReturnType<typeof pair>; test: ReturnType<typeof pair> };
  validationImproved: boolean;
  inputAuditPassed: boolean;
  overlappingTrainingContracts: number;
  sharedValidationTestWindows: number;
  seenSkeletonCount: number;
  unseenSkeletonCount: number;
};

export function windowComparison(value: unknown, checkpointSha: unknown): WindowComparison | null {
  const root = fields(value);
  if (
    root.schemaVersion !== 1 ||
    typeof checkpointSha !== "string" ||
    !/^[a-f0-9]{64}$/.test(checkpointSha) ||
    root.checkpointSha256 !== checkpointSha
  )
    return null;
  const prefix = fields(root.prefix),
    windows = fields(root.windows);
  const result = {
    prefix: { validation: pair(prefix.validation), test: pair(prefix.test) },
    windows: { validation: pair(windows.validation), test: pair(windows.test) },
  };
  if (
    [
      result.prefix.validation,
      result.prefix.test,
      result.windows.validation,
      result.windows.test,
    ].some((p) => p.micro === null || p.macro === null)
  )
    return null;
  const names = [
    "overlappingTrainingContracts",
    "sharedValidationTestWindows",
    "seenSkeletonCount",
    "unseenSkeletonCount",
  ] as const;
  if (
    names.some((name) => count(root[name]) === null) ||
    typeof root.validationImproved !== "boolean" ||
    typeof root.inputAuditPassed !== "boolean"
  )
    return null;
  const improved =
    (result.windows.validation.micro as number) > (result.prefix.validation.micro as number) &&
    (result.windows.validation.macro as number) > (result.prefix.validation.macro as number);
  const auditPassed =
    root.overlappingTrainingContracts === 0 && root.sharedValidationTestWindows === 0;
  if (root.validationImproved !== improved || root.inputAuditPassed !== auditPassed) return null;
  return {
    ...result,
    validationImproved: root.validationImproved,
    inputAuditPassed: root.inputAuditPassed,
    overlappingTrainingContracts: root.overlappingTrainingContracts as number,
    sharedValidationTestWindows: root.sharedValidationTestWindows as number,
    seenSkeletonCount: root.seenSkeletonCount as number,
    unseenSkeletonCount: root.unseenSkeletonCount as number,
  };
}
