import assert from 'node:assert/strict';
import test from 'node:test';
import { sha3_256 } from 'js-sha3';
import { classifyPocEvidence, findingPocEvidence } from './poc-evidence.ts';

const code = 'contract PoC { function test_exploit() public { assert(true); } }';
const address = '0x' + '1'.repeat(40);
const logs = `[SmartPoC | Foundry] target=${address} chain=1 tests=1\nExecuted source SHA3-256: ${sha3_256(code)}\n[PASS] test_exploit()\n1 passed; 0 failed`;
const result = { status: 'passed', logs, runAt: '2026-10-20T08:00:00Z', executedSource: code };

test('template and generated code are labeled before any execution', () => {
  assert.equal(classifyPocEvidence({ code, origin: 'template' }).stage, 'template');
  assert.equal(classifyPocEvidence({ code, origin: 'generated' }).stage, 'generated');
});

test('a passing source-bound non-sanity test is labeled reproduced', () => {
  assert.equal(classifyPocEvidence({ code, result, target: address, chainId: 'ethereum' }).stage, 'reproduced');
});

test('a passed flag or legacy logs alone are never reproduction evidence', () => {
  for (const bad of [{ ...result, logs: 'passed' }, { ...result, logs: logs.replace(/Executed source SHA3-256: .*\n/, '') }, { ...result, runAt: '' }]) {
    assert.notEqual(classifyPocEvidence({ code, result: bad }).stage, 'reproduced');
  }
});

test('edits and a mismatched chain or target invalidate reproduction', () => {
  for (const input of [{ code: code + ' // edited', result }, { code, result, target: '0x' + '2'.repeat(40) }, { code, result, target: '' }, { code, result, chainId: 'base' }]) {
    assert.notEqual(classifyPocEvidence(input).stage, 'reproduced');
  }
});

test('zero-test, sanity-only, and placeholder proofs cannot be reproduced', () => {
  for (const output of [logs.replace('tests=1', 'tests=0'), logs.replace('test_exploit', 'test_forkSanity'), logs.replace('[PASS] test_exploit()', ''), logs + '\nTEMPLATE_NOT_ADAPTED']) {
    assert.notEqual(classifyPocEvidence({ code, result: { ...result, logs: output } }).stage, 'reproduced');
  }
  assert.notEqual(classifyPocEvidence({ code: '// TEMPLATE_NOT_ADAPTED\n' + code, result }).stage, 'reproduced');
  assert.notEqual(classifyPocEvidence({ code, origin: 'template', result }).stage, 'reproduced');
});

test('failures and unavailable execution stay separate from code origin and safety', () => {
  for (const status of ['failed', 'error', 'backend_unreachable', 'skipped']) {
    const evidence = classifyPocEvidence({ code, origin: 'generated', result: { ...result, status } });
    assert.equal(evidence.stage, 'generated');
    assert.doesNotMatch(evidence.description, /target is safe/i);
  }
});

test('saved findings require a binding to the current finding input as well as executed code', () => {
  const finding = { exploitSolidity: 'original snippet', pocCode: code, pocStatus: 'passed', pocRunAt: result.runAt,
    pocOutput: `Finding input SHA3-256: ${sha3_256('original snippet')}\n${logs}` };
  assert.equal(findingPocEvidence(finding).stage, 'reproduced');
  assert.notEqual(findingPocEvidence({ ...finding, exploitSolidity: 'edited snippet' }).stage, 'reproduced');
  assert.notEqual(findingPocEvidence({ ...finding, pocOutput: logs }).stage, 'reproduced');
});
