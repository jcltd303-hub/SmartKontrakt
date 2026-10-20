import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { POC_FALLBACK_TEMPLATES } from '../src/lib/audit/poc-fallbacks.ts';

test('all indexed PoC fallback harnesses have the expected structure and embedded source', async () => {
  const directory = new URL('../foundry/poc-fallbacks/', import.meta.url);
  const index = JSON.parse(await readFile(new URL('index.json', directory), 'utf8'));
  const files = (await readdir(directory)).filter(f => f.endsWith('.t.sol')).sort();
  assert.equal(files.length, 45, 'Should have 45 PoC fallback files');
  assert.deepEqual(index.fallbacks.map(f => f.file).sort(), files);
  assert.deepEqual(Object.keys(POC_FALLBACK_TEMPLATES).sort(), files);

  for (const file of files) {
    const source = await readFile(new URL(file, directory), 'utf8');
    assert.match(source, /contract PoC is Test/, `${file}: missing PoC contract`);
    assert.match(source, /function test_/, `${file}: missing test function`);
    assert.equal(POC_FALLBACK_TEMPLATES[file], source, `${file}: regenerate embedded template`);
  }
});

test('unadapted success-only scenarios cannot masquerade as exploit reproductions', async () => {
  const { createRequire } = await import('node:module');
  const { parse } = createRequire(import.meta.url)('@solidity-parser/parser');
  for (const file of ['07b-unprotected-visibility.t.sol', '42-short-address-attack.t.sol', '43-front-running.t.sol', '44-external-contract-ref.t.sol']) {
    const source = await readFile(new URL(`../foundry/poc-fallbacks/${file}`, import.meta.url), 'utf8');
    const ast = parse(source);
    const contract = ast.children.find(node => node.type === 'ContractDefinition' && node.name === 'PoC');
    const tests = contract.subNodes.filter(node => node.type === 'FunctionDefinition' && node.name.startsWith('test_'));
    assert.ok(tests.length > 0);
    for (const fn of tests) {
      const first = fn.body.statements[0];
      assert.equal(first.type, 'ExpressionStatement', `${file}: placeholder must stop before arbitrary calls`);
      assert.equal(first.expression.type, 'FunctionCall');
      assert.equal(first.expression.expression.name, 'revert');
      assert.match(first.expression.arguments[0].value, /TEMPLATE_NOT_ADAPTED/);
    }
  }
});
