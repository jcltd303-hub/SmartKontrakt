import { savePocRun, type PocRunSupabaseConfig } from '../poc-runs.ts';
import type { PocResult } from './types.ts';

/** Standalone editor/manual runs use the same durable run schema as findings. */
export async function saveSmartPocResult(
  result: PocResult, source: string, chainId: number, config: PocRunSupabaseConfig,
): Promise<'saved' | 'not-configured' | 'not-run'> {
  if (!result.evidence || result.status === 'skipped' || result.status === 'backend_unreachable') return 'not-run';
  if (!config.enabled) return 'not-configured';
  await savePocRun({ id: crypto.randomUUID(), source,
    status: result.status, startedAt: result.evidence.startedAt, finishedAt: result.runAt,
    durationMs: Math.max(0, Math.round(result.durationMs)), chainId, exitCode: null,
    output: result.logs.slice(0, 1_000_000), truncated: result.logs.length > 1_000_000,
  }, config);
  return 'saved';
}
