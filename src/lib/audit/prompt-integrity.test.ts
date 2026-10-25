import test from 'node:test';
import assert from 'node:assert/strict';
import { buildAiReviewPrompt, generateAiSecurityReview } from './ai-review.server.ts';
import { selectPocFallbacks } from './poc-fallbacks.ts';
import { buildPocGenerationPrompt } from './smartpoc/prompts.ts';
import type { Finding } from './types.ts';
const finding = { detector: 'unregistered-detector', severity: 'medium', title: 'Authorization invariant', summary: 'Unauthorized caller changes owner', confidence: 'high' } as Finding;

test('unregistered detector cannot inherit unrelated other-category templates', () => {
  assert.deepEqual(selectPocFallbacks([finding]), []);
  assert.ok(selectPocFallbacks([{ detector: 'reentrancy', severity: 'high' }]).length > 0);
});
test('review asks for evidence appropriate to the finding without selector guessing or preconfirmation', () => {
  const { user } = buildAiReviewPrompt('Target', 'contract Target {}', [finding]);
  assert.doesNotMatch(user, /assert a balance\/profit change|try at least kill\(\)|tests and confirms the primary vulnerability|proven, fork-ready/i);
  assert.match(user, /finding-specific observable invariant/i);
  assert.match(user, /actual ABI|gathered ABI/i);
  assert.match(user, /unconfirmed until/i);
});
test('SmartPoC keeps gathered ABI and does not prime every finding with reentrancy', () => {
  const { user } = buildPocGenerationPrompt({ contractName: 'Target', buildMetadata: '', finding, bugContext: '', targetAbiSection: 'function setOwner(address next) external;' });
  assert.match(user, /function setOwner\(address next\)/);
  assert.doesNotMatch(user, /One-shot example|re-enters `withdraw`/);
  assert.match(user, /finding-specific observable invariant/i);
});
test('unavailable review with no findings invents neither exploit nor architecture', async () => {
  const old = process.env.OPENROUTER_API_KEY;
  delete process.env.OPENROUTER_API_KEY;
  try {
    const review = await generateAiSecurityReview('Target', '0x00', []);
    assert.match(review.threatModelReport, /unavailable/i);
    assert.match(review.threatModelReport, /0 .*finding/i);
    assert.doesNotMatch(review.threatModelReport + review.economicRiskSummary, /Potential Reentrancy|First Deposit|exposes public state-mutating|high\/critical vulnerabilities/i);
  } finally { if (old === undefined) delete process.env.OPENROUTER_API_KEY; else process.env.OPENROUTER_API_KEY = old; }
});
test('review bounds ABI evidence and distinguishes unavailable screening', () => {
  const inventory = { abiSource: 'heuristic', abi: Array.from({ length: 80 }, (_, i) => ({ type: 'function', name: `fn${i}`, inputs: [] })), notes: [] };
  const { user } = buildAiReviewPrompt('Target', '', [], undefined, inventory);
  assert.match(user, /ABI provenance: heuristic/);
  assert.match(user, /unavailable|not run/i);
  assert.match(user, /fn39/);
  assert.doesNotMatch(user, /fn40/);
  assert.match(user, /not.*confirmed|not.*probability/i);
});
test('review carries every ResNet class with provenance and bounded score semantics', () => {
  const labels = ['access-control', 'arithmetic', 'reentrancy', 'unchecked-calls', 'others'];
  const result = { modelId: 'test-model', architecture: 'ResNet1D', checkpointSha256: 'a'.repeat(64), predictions: labels.map((label) => ({ label, score: 0.3, threshold: 0.5, flagged: false })), inputBytes: 55, truncated: false, processedBytes: 55, windows: 1, policy: 'consecutive-16384-zero-pad-l2-class-max-v1', ranAt: '2026-10-25' };
  const { user } = buildAiReviewPrompt('Target', '', [], undefined, {}, result);
  for (const label of labels) assert.match(user, new RegExp(label));
  assert.match(user, /test-model/);
  assert.match(user, /checkpointSha256/);
  assert.match(user, /"processedBytes":55/);
  assert.match(user, /"windows":1/);
  assert.match(user, /consecutive-16384-zero-pad-l2-class-max-v1/);
  assert.match(user, /not calibrated probabilities or confirmed vulnerabilities/);
});
test('screening failure and coverage survive evidence rendering', () => {
  const failed = buildAiReviewPrompt('Target', '', [], undefined, { resnetStatus: { status: 'error', error: 'model load failed' } }).user;
  assert.match(failed, /model load failed/);
  assert.match(failed, /"status":"error"/);
  const missing = buildAiReviewPrompt('Target', '', []).user;
  assert.doesNotMatch(missing, /model load failed/);
});
test('review evidence input sanitizer preserves bounded selected fields and rejects malformed ML', async () => {
  const module = await import('./audit-evidence.ts');
  assert.equal(typeof module.cleanReviewEvidence, 'function');
  const input = { inventory: { abiSource: 'sourcify', abi: Array.from({length: 100}, () => ({ type: 'function', name: 'owner', inputs: [] })), disassembly: 'must not travel', resnetStatus: { status: 'error', error: 'load failed' } }, resnet: { predictions: [] } };
  const clean = module.cleanReviewEvidence(input.inventory, input.resnet);
  assert.equal(clean.inventory?.abi?.length, 40);
  assert.equal(clean.inventory?.abiSource, 'sourcify');
  assert.equal(clean.inventory?.resnetStatus?.error, 'load failed');
  assert.equal(clean.inventory?.disassembly, undefined);
  assert.equal(clean.resnet, null);
});
