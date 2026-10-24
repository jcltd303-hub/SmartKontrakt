import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runSmartPoc, needsSmartPoc } from './foundry-backend.ts';
import { clearValueCache } from './value.ts';

/**
 * Route mocked fetches. The pre-run value check now hits three sources (JSON-RPC
 * for the native balance, Blockscout for tokens + native price, DefiLlama for
 * leftovers), so tests answer those separately and observe only backend traffic.
 */
function installFetch(opts: {
  balance?: string;
  coinPrice?: string | null;
  tokens?: unknown[];
  tokensDown?: boolean;
  llama?: Record<string, { price: number }>;
  reply?: (n: number, body: { rpcUrl?: string; method?: string }) => Response;
} = {}) {
  const original = globalThis.fetch;
  const backend: Array<{ url: string; body: { rpcUrl?: string; method?: string } }> = [];
  globalThis.fetch = (async (input: unknown, init?: { body?: unknown }) => {
    const url = String(input);
    if (url.includes('blockscout')) {
      if (url.includes('/stats')) {
        if (opts.coinPrice === null) return new Response('down', { status: 500 });
        return new Response(JSON.stringify({ coin_price: opts.coinPrice ?? '2500' }));
      }
      if (opts.tokensDown) return new Response('down', { status: 500 });
      return new Response(JSON.stringify(opts.tokens ?? []));
    }
    if (url.includes('coins.llama.fi')) {
      return new Response(JSON.stringify({ coins: opts.llama ?? {} }));
    }
    const body = JSON.parse(String(init?.body ?? '{}'));
    if (body.method === 'eth_getBalance') {
      return new Response(JSON.stringify({ result: opts.balance ?? '0x1' }));
    }
    backend.push({ url, body });
    return opts.reply
      ? opts.reply(backend.length, body)
      : new Response(JSON.stringify({ ok: true, passed: true, logs: '1 passed; 0 failed', durationMs: 1 }));
  }) as typeof fetch;
  clearValueCache();
  return { backend, restore: () => { globalThis.fetch = original; } };
}

const ADDR = '0x' + '1'.repeat(40);

test('SmartPoC classifies zero-test success as no_tests (not an error, not a verdict) and records execution evidence', async () => {
  const f = installFetch({ reply: () => new Response(JSON.stringify({ok:true,passed:true,logs:'No tests found',durationMs:1})) });
  try {
    const result = await runSmartPoc('http://localhost:8787', {address:ADDR,testCode:'contract PoC { function test_exploit() public {} }'});
    assert.equal(result.status, 'no_tests');
    assert.match(result.logs, /SmartPoC/);
    assert.match(result.logs, /SHA-256/);
    assert.equal(result.evidence?.engine, 'foundry');
    assert.equal(result.evidence?.testCount, 0);
  } finally { f.restore(); }
});

test('SmartPoC keeps Base RPC retries on Base and records real test counts', async () => {
  const f = installFetch({ reply: () => new Response(JSON.stringify({ok:true,passed:true,logs:'[PASS] testProof()\n1 passed; 0 failed',durationMs:2})) });
  try {
    const result = await runSmartPoc('http://localhost:8787', {address:ADDR,testCode:'contract PoC { function test_exploit() public {} }',chainId:8453});
    assert.equal(result.status,'passed');
    assert.equal(result.evidence?.testCount,1);
    assert.equal(result.evidence?.chainId,"8453");
    assert.ok(f.backend.length > 0);
    assert.ok(String(f.backend[0].body.rpcUrl).includes('base'));
  } finally { f.restore(); }
});

test('saved findings require matching completed execution evidence', () => {
  assert.equal(needsSmartPoc({exploitSolidity:'code'}),true);
  assert.equal(needsSmartPoc({exploitSolidity:'code',pocCode:'old',pocStatus:'passed',pocRunAt:new Date().toISOString()}),true);
  assert.equal(needsSmartPoc({exploitSolidity:'code',pocCode:'code',pocStatus:'passed',pocRunAt:new Date().toISOString(),pocOutput:'[SmartPoC | Foundry] tests=1\nSHA-256: proof'}),false);
  assert.equal(needsSmartPoc({exploitSolidity:''}),false);
});

test('saved audit queue runs only missing high severity proofs and stops on backend outage', async () => {
  const { runMissingSmartPocs } = await import('./foundry-backend.ts');
  const visited: string[] = [];
  await runMissingSmartPocs([
    {id:'done',severity:'critical',exploitSolidity:'a',pocCode:'a',pocStatus:'passed',pocRunAt:'2026-10-20',pocOutput:'[SmartPoC | Foundry] tests=1\nSHA-256: proof'},
    {id:'low',severity:'low',exploitSolidity:'b'},
    {id:'missing',severity:'high',exploitSolidity:'c'},
    {id:'later',severity:'critical',exploitSolidity:'d'},
  ], async finding => { visited.push(finding.id); return {status:'backend_unreachable'}; });
  assert.deepEqual(visited,['missing']);
});

test('legacy passed flags without execution logs are rerun', () => { assert.equal(needsSmartPoc({exploitSolidity:'x',pocCode:'x',pocStatus:'passed',pocRunAt:'2026-10-20'}),true); });

test('SmartPoC skips the run when the target holds no value at all', async () => {
  const f = installFetch({ balance: '0x0', tokens: [] });
  try {
    const result = await runSmartPoc('http://localhost:8787', {address:ADDR,testCode:'contract PoC {}'});
    assert.equal(result.status, 'skipped');
    assert.match(result.logs, /holds no value/);
    assert.equal(f.backend.length, 0, 'the backend must not be called for a zero-value target');
  } finally { f.restore(); }
});

test('SmartPoC still runs when only an ERC-20 holding carries the value', async () => {
  // Zero ETH, but one priced token: exactly the case the native-only guard got wrong.
  const f = installFetch({
    balance: '0x0',
    tokens: [{ token: { address_hash: '0x'+'a'.repeat(40), decimals: '18', exchange_rate: '1.5', symbol: 'TKN', name: 'Token', type: 'ERC-20' }, value: '1000000000000000000' }],
  });
  try {
    const result = await runSmartPoc('http://localhost:8787', {address:ADDR,testCode:'contract PoC { function test_exploit() public {} }'});
    assert.equal(result.status, 'passed');
    assert.equal(f.backend.length, 1);
  } finally { f.restore(); }
});

test('skipZeroValue:false forces the run on a zero-value target', async () => {
  const f = installFetch({ balance: '0x0', tokens: [] });
  try {
    const result = await runSmartPoc('http://localhost:8787', {address:ADDR,testCode:'contract PoC { function test_exploit() public {} }',skipZeroValue:false});
    assert.equal(result.status, 'passed');
  } finally { f.restore(); }
});

test('an incomplete valuation (token indexer down) does NOT skip the run', async () => {
  const f = installFetch({ balance: '0x0', tokensDown: true });
  try {
    const result = await runSmartPoc('http://localhost:8787', {address:ADDR,testCode:'contract PoC { function test_exploit() public {} }'});
    assert.equal(result.status, 'passed', 'unknown value must never be treated as zero');
  } finally { f.restore(); }
});

test('an unpriced token holding does NOT skip the run', async () => {
  // Balance read, tokens read, but the token has no price — the total is a floor.
  const f = installFetch({
    balance: '0x0',
    coinPrice: '2500',
    tokens: [{ token: { address_hash: '0x'+'b'.repeat(40), decimals: '18', exchange_rate: null, symbol: 'NOPRICE', name: 'X', type: 'ERC-20' }, value: '5000000000000000000' }],
  });
  try {
    const result = await runSmartPoc('http://localhost:8787', {address:ADDR,testCode:'contract PoC { function test_exploit() public {} }'});
    assert.equal(result.status, 'passed');
  } finally { f.restore(); }
});

test('standalone SmartPoC persistence never saves an unexecuted proof', async () => {
  const { saveSmartPocResult } = await import('./smart-poc-save.ts');
  assert.equal(await saveSmartPocResult({status:'skipped',logs:'No target',durationMs:0,runAt:new Date().toISOString()},'code',1,{url:'',anonKey:'',enabled:true}), 'not-run');
});

test('standalone persistence saves the executed source and complete evidence', async () => {
  const { saveSmartPocResult } = await import('./smart-poc-save.ts');
  const original = globalThis.fetch;
  let row: Record<string, unknown> | undefined;
  globalThis.fetch = async (_url, init) => {
    row = JSON.parse(String(init?.body))[0];
    return new Response(null,{status:201});
  };
  try {
    const now = new Date().toISOString();
    const result = await saveSmartPocResult({status:'passed',logs:'[SmartPoC | Foundry] tests=1',durationMs:3,runAt:now,
      evidence:{engine:'foundry',startedAt:now,finishedAt:now,target:ADDR,chainId:'8453',sourceHash:'hash',backendUrl:'http://localhost:8787',rpcUrls:[],testCount:1}},
      'executed source',8453,{url:'https://test.supabase.co',anonKey:'sb_publishable_test',enabled:true});
    assert.equal(result,'saved');
    assert.equal(row?.source,'executed source');
    assert.equal(row?.chain_id,8453);
    assert.match(String(row?.output),/SmartPoC/);
  } finally { globalThis.fetch = original; }
});

test('SmartPoC repairs a compile failure once and records the code actually executed', async () => {
  let repairs = 0;
  const f = installFetch({
    reply: (n) => new Response(JSON.stringify(n === 1
      ? {ok:true,passed:false,logs:'Compiler run failed: TypeError',durationMs:1}
      : {ok:true,passed:true,logs:'1 passed; 0 failed',durationMs:1})),
  });
  try {
    const result = await runSmartPoc('http://localhost:8787',{address:ADDR,testCode:'contract PoC { function test_exploit() public { broken } }',
      repair: async () => { repairs++; return 'contract PoC { function test_exploit() public {} }'; }});
    assert.equal(result.status,'passed');
    assert.equal(result.executedSource,'contract PoC { function test_exploit() public {} }');
    assert.equal(repairs,1);
    assert.equal(f.backend.length,2);
  } finally { f.restore(); }
});

test("a repaired proof is reused only while its original finding input is unchanged", async () => {
  const {pocInputDigest} = await import("./foundry-backend.ts");
  const f = {exploitSolidity:"original",pocCode:"repaired test",pocStatus:"passed",pocRunAt:"2026-10-20",pocOutput:`Finding input SHA3-256: ${pocInputDigest("original")}\n[SmartPoC | Foundry] tests=1`};
  assert.equal(needsSmartPoc(f),false);
  assert.equal(needsSmartPoc({...f,exploitSolidity:"changed"}),true);
});

test('SmartPoC binds the executed source for synchronous UI evidence labels', async () => {
  const { classifyPocEvidence } = await import('./poc-evidence.ts');
  const f = installFetch({ reply: () => new Response(JSON.stringify({ok:true,passed:true,logs:'[PASS] test_exploit()\n1 passed; 0 failed',durationMs:1})) });
  try {
    const code = 'contract PoC { function test_exploit() public {} }';
    const result = await runSmartPoc('http://localhost:8787', {address:ADDR,testCode:code});
    assert.equal(classifyPocEvidence({code,result}).stage,'reproduced');
    assert.notEqual(classifyPocEvidence({code:code+' // edited',result}).stage,'reproduced');
  } finally { f.restore(); }
});

test('SmartPoC gate: a test-less draft returns no_tests and NEVER reaches the backend', async () => {
  // The hollow-pass shape from the live page: the SmartPoC engine's
  // draft was a bare attack contract — no Test contract, no test
  // function. The gate must refuse before any backend traffic (the
  // value guard is disabled here so only the gate can stop the run).
  const f = installFetch();
  try {
    const draft = 'contract Attack { function poke(address t) public { t.call(""); } }';
    const result = await runSmartPoc('http://localhost:8787', {address:ADDR,testCode:draft,skipZeroValue:false});
    assert.equal(result.status, 'no_tests');
    assert.equal(f.backend.length, 0, 'the backend fetch must never be called for a test-less draft');
    assert.match(result.logs, /tests=0/);
    assert.match(result.logs, /no executable test function/);
    assert.match(result.logs, /did not include a Test contract/);
    assert.equal(result.evidence?.testCount, 0);
    assert.equal(result.executedSource, draft);
  } finally { f.restore(); }
});

test('SmartPoC gate: a draft WITH a test function proceeds to the backend', async () => {
  const f = installFetch({ reply: () => new Response(JSON.stringify({ok:true,passed:true,logs:'Suite result: ok. 1 passed; 0 failed; 0 skipped',durationMs:2})) });
  try {
    const result = await runSmartPoc('http://localhost:8787', {address:ADDR,testCode:'contract PoC { function test_exploit() public {} }',skipZeroValue:false});
    assert.equal(result.status, 'passed');
    assert.equal(f.backend.length, 1, 'a test-bearing draft must reach the backend exactly once');
    assert.equal(result.evidence?.testCount, 1);
  } finally { f.restore(); }
});

test('SmartPoC maps a backend noTests response to no_tests (not failed)', async () => {
  // New-backend contract: forge completed, executed 0 tests, and says
  // so (noTests/testsRun) instead of claiming a hollow pass.
  const f = installFetch({ reply: () => new Response(JSON.stringify({ok:true,passed:false,noTests:true,testsRun:0,logs:'Warning: No tests found in project! Forge looks for functions that start with `test`',durationMs:2})) });
  try {
    const result = await runSmartPoc('http://localhost:8787', {address:ADDR,testCode:'contract PoC { function test_exploit() public {} }',skipZeroValue:false});
    assert.equal(result.status, 'no_tests');
    assert.equal(result.evidence?.testCount, 0);
    assert.match(result.logs, /tests=0/);
  } finally { f.restore(); }
});
