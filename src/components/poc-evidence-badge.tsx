import type { PocEvidence } from '../lib/audit/poc-evidence';

/** One evidence vocabulary for live results, saved findings and manual runs. */
export function PocEvidenceBadge({ evidence }: { evidence: PocEvidence }) {
  return (
    <span className="inline-flex flex-col gap-1 text-xs font-mono min-w-0" data-poc-evidence={evidence.stage}>
      <span className={`font-bold ${evidence.stage === 'reproduced' ? 'text-emerald-400' : evidence.stage === 'generated' ? 'text-amber-300' : 'text-stone-400'}`}>
        {evidence.label}
      </span>
      <span className="text-stone-400 break-words">{evidence.description}</span>
    </span>
  );
}
