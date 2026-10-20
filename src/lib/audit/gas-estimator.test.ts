import { test } from 'node:test';
import assert from 'node:assert/strict';
import { disassemble } from './disassemble.ts';
import { estimateGasAndDetectDos } from './gas-estimator.ts';

const estimate = (hex: string) =>
  estimateGasAndDetectDos(disassemble(Uint8Array.from(Buffer.from(hex, 'hex'))));

for (const [name, hex] of [
  ['JUMP with PUSH1', '5b54600056'],
  ['JUMPI with PUSH2', '5b54600161000057'],
  ['JUMP with PUSH0', '5b545f56'],
]) {
  test(`detects a storage loop in disassembled ${name} bytecode`, () => {
    assert.equal(estimate(hex).unboundedStorageWarning, true);
  });
}

test('does not flag straight-line storage access', () => {
  assert.equal(estimate('60015500').unboundedStorageWarning, false);
});

test('does not flag storage outside the backward jump interval', () => {
  assert.equal(estimate('545b600156').unboundedStorageWarning, false);
});

test('does not treat an unrelated PUSH as a dynamic jump destination', () => {
  assert.equal(estimate('5b5460003556').unboundedStorageWarning, false);
});

test('does not flag a forward jump or a loop without storage', () => {
  assert.equal(estimate('600456005b5400').unboundedStorageWarning, false);
  assert.equal(estimate('5b600056').unboundedStorageWarning, false);
});
