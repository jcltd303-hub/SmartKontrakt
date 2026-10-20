import { test } from 'node:test';
import assert from 'node:assert/strict';
import { estimateGasAndDetectDos } from './gas-estimator.ts';

test('detects unbounded loop with storage', () => {
    // Jump loop with SLOAD inside
    // JUMPDEST(0) ... SLOAD(1) ... PUSH1 0 JUMP(2)
    const instructions = [
        { pc: 0, name: 'JUMPDEST', imm: null },
        { pc: 1, name: 'SLOAD', imm: null },
        { pc: 2, name: 'PUSH1', imm: '00' },
        { pc: 4, name: 'JUMP', imm: '00' },
    ];
    const estimate = estimateGasAndDetectDos(instructions);
    assert.equal(estimate.unboundedStorageWarning, true);
});

test('does not flag simple code', () => {
    const instructions = [
        { pc: 0, name: 'PUSH1', imm: '01' },
        { pc: 2, name: 'SSTORE', imm: null },
        { pc: 3, name: 'STOP', imm: null },
    ];
    const estimate = estimateGasAndDetectDos(instructions);
    assert.equal(estimate.unboundedStorageWarning, false);
});
