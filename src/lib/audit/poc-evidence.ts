import { sha3_256 } from 'js-sha3';

export type PocOrigin = 'template' | 'generated';
export type PocEvidence = {
  stage: PocOrigin | 'reproduced';
  label: string;
  description: string;
};
export type PocEvidenceResult = {
  status: string;
  logs?: string | null;
  runAt?: string | null;
  executedSource?: string | null;
};
export type PocEvidenceInput = {
  code?: string | null;
  origin?: PocOrigin;
  result?: PocEvidenceResult | null;
  target?: string | null;
  chainId?: string | number | null;
};

function chainNumber(chain: string | number): string {
  const ids: Record<string, string> = { ethereum: '1', arbitrum: '42161', base: '8453', optimism: '10', polygon: '137', bsc: '56' };
  return ids[String(chain).toLowerCase()] ?? String(chain);
}

/** Code origin and execution are different facts. Fail closed for historical
 * bare verdicts, edits, placeholders and tests that only check fork setup.
 * Reproduced means the recorded test assertions passed, not an independent
 * assessment that those assertions prove an exploitable vulnerability. */
export function classifyPocEvidence(input: PocEvidenceInput): PocEvidence {
  const code = input.code ?? '';
  const result = input.result;
  const origin = input.origin ?? (code.includes('TEMPLATE_NOT_ADAPTED') ? 'template' : 'generated');
  const base = { stage: origin, label: origin === 'template' ? 'Template' : 'Generated PoC' };
  if (!code.trim()) return { stage: 'template', label: 'No PoC', description: 'No test code is available.' };
  if (!result) return { ...base, description: origin === 'template' ? 'Starting point only. Adapt and run before claiming reproduction.' : 'Code is available; reproduction has not been evidenced.' };
  if (result.status === 'failed') return { ...base, description: 'Not reproduced: test assertions failed. This does not establish safety.' };
  if (result.status === 'skipped') return { ...base, description: 'Not run: execution was skipped.' };
  if (result.status !== 'passed') return { ...base, description: 'Execution error or backend unavailable. No reproduction verdict.' };
  const logs = result.logs ?? '';
  const unverified = (description: string): PocEvidence => ({ ...base, description });
  if (origin === 'template' || /TEMPLATE_NOT_ADAPTED/.test(code + logs)) return unverified('Template execution is not exploit reproduction. Target-specific assertions are required.');
  const header = logs.match(/^\[SmartPoC \| Foundry\] target=(0x[\da-fA-F]{40}) chain=(\S+) tests=(\d+)\s*$/m);
  if (!header || Number(header[3]) < 1 || !result.runAt || !Number.isFinite(Date.parse(result.runAt))) {
    return unverified('Execution unverified: no complete nonzero-test Foundry evidence. Rerun this PoC.');
  }
  if (input.target != null && header[1].toLowerCase() !== input.target.toLowerCase() ||
      input.chainId != null && chainNumber(header[2]) !== chainNumber(input.chainId)) {
    return unverified('Execution belongs to a different target or chain. Rerun this PoC.');
  }
  const digest = logs.match(/^Executed source SHA3-256: ([\da-f]{64})\s*$/m)?.[1];
  if (digest !== sha3_256(code) || result.executedSource != null && result.executedSource !== code) {
    return unverified('Execution unverified or source changed. Rerun the current code.');
  }
  const passedNames = [...logs.matchAll(/^\s*\[PASS\]\s+([a-zA-Z_]\w*)\s*\(/gm)].map(match => match[1]);
  if (!passedNames.some(name => !/^test_?(forksanity|targethascode|sanity)$/i.test(name))) {
    return unverified('Only setup checks or unnamed tests were evidenced. Exploit reproduction is unverified.');
  }
  return { stage: 'reproduced', label: 'Reproduced', description: 'Source-matched Foundry test assertions passed. Review the assertions to assess exploit validity.' };
}

/** Saved finding rows retain both executed code and evidence logs. An adapted
 * or repaired harness must also be bound to the current original finding. */
export function findingPocEvidence(finding: {
  exploitSolidity?: string | null; pocCode?: string | null; pocStatus?: string | null;
  pocOutput?: string | null; pocRunAt?: string | null; targetAddress?: string | null; chainId?: string | null;
}): PocEvidence {
  const code = finding.pocCode || finding.exploitSolidity;
  const result = finding.pocStatus ? { status: finding.pocStatus, logs: finding.pocOutput, runAt: finding.pocRunAt } : null;
  const evidence = classifyPocEvidence({ code, origin: finding.pocCode ? 'generated' : 'template', result,
    target: finding.targetAddress, chainId: finding.chainId });
  if (evidence.stage === 'reproduced' && finding.exploitSolidity && code !== finding.exploitSolidity &&
      !finding.pocOutput?.includes(`Finding input SHA3-256: ${sha3_256(finding.exploitSolidity)}`)) {
    return { stage: 'generated', label: 'Generated PoC', description: 'Finding input changed or has no matching execution binding. Rerun this PoC.' };
  }
  return evidence;
}
