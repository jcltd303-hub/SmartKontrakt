import { test } from 'node:test';
import assert from 'node:assert/strict';
import { estimateGasAndDetectDos } from './gas-estimator.ts';

test('detects unbounded loop with storage', () => {
    // Jump loop with SLOAD inside
    // JUMPDEST(0) ... SLOAD(1) ... PUSH1 0 JUMP(2)
    const instructions = [
        { pc: 0, op: 0x5b, name: 'JUMPDEST' },
        { pc: 1, op: 0x54, name: 'SLOAD' },
        { pc: 2, op: 0x60, name: 'PUSH1', imm: '00' },
        { pc: 4, op: 0x56, name: 'JUMP', imm: '00' },
    ];
    const estimate = estimateGasAndDetectDos(instructions);
    assert.equal(estimate.unboundedStorageWarning, true);
});

test('does not flag simple code', () => {
    const instructions = [
        { pc: 0, op: 0x60, name: 'PUSH1', imm: '01' },
        { pc: 2, op: 0x55, name: 'SSTORE' },
        { pc: 3, op: 0x00, name: 'STOP' },
    ];
    const estimate = estimateGasAndDetectDos(instructions);
    assert.equal(estimate.unboundedStorageWarning, false);
});
