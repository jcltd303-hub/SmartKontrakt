import type { FpMatch } from "../lib/audit/fp-signatures";

/**
 * G7 annotation chip: this finding's shape matches a false-positive
 * pattern the auditor confirmed from their own false_positive
 * dispositions (fp-signatures.ts). ANNOTATION ONLY — the finding keeps
 * its severity, its PoC eligibility, and its queue state; the chip
 * exists so a re-scan of a known FP shape is recognized at a glance
 * instead of re-triaged from scratch.
 */
export function FpMatchBadge({ match }: { match: FpMatch }) {
  return (
    <span
      className="px-2 py-1 rounded text-[10px] font-mono font-bold border bg-violet-500/10 text-violet-300 border-violet-500/30"
      title={`Matches a confirmed FP pattern — detector ${match.detector}, title pattern "${match.titlePattern}". Derived from findings the auditor disposed as false_positive. Annotation only: severity, PoC eligibility and disposition are unaffected.`}
    >
      matches confirmed FP pattern
    </span>
  );
}
