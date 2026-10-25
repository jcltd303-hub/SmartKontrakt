import { evaluationSummary, inputCoverage, type WindowComparison } from "@/lib/image-ml/insights";

const f1 = (value: number | null) => (value === null ? "Unavailable" : value.toFixed(4));
const samples = (value: number | null) => (value === null ? "Unavailable" : value.toLocaleString());

export function BytecodeCoverage({ bytes }: { bytes: number }) {
  const coverage = inputCoverage(bytes);
  return (
    <section
      aria-label="Bytecode coverage"
      className="rounded-lg border border-line bg-bg p-3 text-fg"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h4 className="font-mono text-xs font-medium">ResNet input coverage</h4>
        <span className="font-mono text-xs text-amber">
          {(coverage.fraction * 100).toFixed(1)}% of raw bytes
        </span>
      </div>
      <progress
        aria-label="Raw bytecode included in ResNet input"
        value={coverage.used}
        max={coverage.total}
        className="mt-3 h-2 w-full appearance-none overflow-hidden rounded-full bg-line [&::-webkit-progress-bar]:bg-line [&::-webkit-progress-value]:bg-amber [&::-moz-progress-bar]:bg-amber"
      />
      <div className="mt-2 flex flex-wrap justify-between gap-2 text-xs text-muted">
        <span>{samples(coverage.used)} bytes read</span>
        <span>
          {samples(coverage.omitted)} {coverage.omitted === 1 ? "byte" : "bytes"} omitted
        </span>
      </div>
      <p className="mt-2 text-xs leading-relaxed text-muted">
        {coverage.omitted > 0
          ? "Only the prefix is evaluated. Vulnerabilities in the omitted tail may be missed."
          : "All supplied bytes fit in the input; shorter inputs are zero-padded."}{" "}
        This measures input coverage, not source-line or vulnerability coverage.
      </p>
    </section>
  );
}

export function ModelEvaluation({
  training,
  evaluation,
}: {
  training: unknown;
  evaluation: unknown;
}) {
  const summary = evaluationSummary(training, evaluation);
  const scores = [
    ["Validation micro F1", summary.validation.micro],
    ["Validation macro F1", summary.validation.macro],
    ["Test micro F1", summary.test.micro],
    ["Test macro F1", summary.test.macro],
  ] as const;
  return (
    <section
      aria-label="Model evaluation"
      className="rounded-lg border border-line bg-bg p-3 text-fg"
    >
      <h4 className="font-mono text-xs font-medium">Measured model evaluation</h4>
      <p className="mt-1 text-xs leading-relaxed text-muted">
        Dataset-level results, not confidence that this contract is vulnerable.
      </p>
      <dl className="mt-3 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {scores.map(([label, value]) => (
          <div key={label} className="min-w-0 rounded-md bg-surface-2 p-3">
            <dt className="text-xs leading-relaxed text-muted">{label}</dt>
            <dd
              className={
                value === null ? "mt-1 text-xs text-muted" : "mt-1 font-mono text-lg font-medium"
              }
            >
              {f1(value)}
            </dd>
          </div>
        ))}
      </dl>
      <dl className="mt-3 grid grid-cols-3 gap-3 text-xs">
        {(
          [
            ["Training", summary.counts.train],
            ["Validation", summary.counts.validation],
            ["Test", summary.counts.test],
          ] as const
        ).map(([label, value]) => (
          <div key={label}>
            <dt className="text-muted">{label}</dt>
            <dd className="mt-1 font-mono">{samples(value)}</dd>
          </div>
        ))}
      </dl>
      <p className="mt-3 text-xs leading-relaxed text-muted">
        Selected epoch: {summary.selectedEpoch ?? "unavailable"} of{" "}
        {summary.epochs ?? "unavailable"}. Known benchmark reused across experiments; Slither labels
        are not confirmed exploits.
      </p>
    </section>
  );
}

export function WindowExperiment({ comparison }: { comparison: WindowComparison }) {
  return (
    <details className="rounded-lg border border-line bg-bg p-3 text-fg">
      <summary className="min-h-11 cursor-pointer font-mono text-xs font-medium leading-relaxed">
        Compare offline window experiment
      </summary>
      <section aria-label="Window experiment" className="space-y-3 text-xs">
        <p className="leading-relaxed text-muted">
          Same trained weights, up to eight 16,384-byte windows. Thresholds selected on validation
          only. Window inference is not enabled in this browser.
        </p>
        <p className="rounded-md bg-surface-2 p-3 font-medium">
          Prefix model retained.{" "}
          {comparison.validationImproved
            ? "Window validation improved."
            : "Window validation did not improve both F1 metrics."}{" "}
          {comparison.inputAuditPassed
            ? "Input overlap audit passed."
            : "Input overlap audit did not pass."}
        </p>
        <table className="w-full table-fixed text-left">
          <caption className="sr-only">Measured prefix and offline window F1 comparison</caption>
          <thead className="text-muted">
            <tr>
              <th className="w-1/2 py-2 pr-2">Dataset / metric</th>
              <th className="px-2">Prefix</th>
              <th className="pl-2">Windows</th>
            </tr>
          </thead>
          <tbody>
            {(
              [
                [
                  "Validation micro",
                  comparison.prefix.validation.micro,
                  comparison.windows.validation.micro,
                ],
                [
                  "Validation macro",
                  comparison.prefix.validation.macro,
                  comparison.windows.validation.macro,
                ],
                ["Test micro", comparison.prefix.test.micro, comparison.windows.test.micro],
                ["Test macro", comparison.prefix.test.macro, comparison.windows.test.macro],
              ] as const
            ).map(([label, prefix, windows]) => (
              <tr key={label} className="border-t border-line">
                <th className="py-3 pr-2 font-normal">{label}</th>
                <td className="px-2 font-mono">{f1(prefix)}</td>
                <td className="pl-2 font-mono">{f1(windows)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="leading-relaxed text-muted">
          Training-overlap contracts: {samples(comparison.overlappingTrainingContracts)}. Shared
          validation/test windows: {samples(comparison.sharedValidationTestWindows)}. An input
          overlap blocks eligibility without removing contracts from the reported cohorts.
        </p>
        <p className="leading-relaxed text-muted">
          Test opcode skeletons: {samples(comparison.seenSkeletonCount)} seen in training or
          validation; {samples(comparison.unseenSkeletonCount)} unseen. This is exact skeleton
          novelty, not semantic-family isolation.
        </p>
      </section>
    </details>
  );
}
