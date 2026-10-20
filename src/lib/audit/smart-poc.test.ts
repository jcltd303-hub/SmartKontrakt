import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runSmartPoc, needsSmartPoc } from './foundry-backend.ts';

test('SmartPoC rejects zero-test success and records execution evidence', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    // Answer the pre-run balance probe with a non-zero balance so the run proceeds.
    if (JSON.parse(String(init?.body ?? "{}")).method === 'eth_getBalance') return new Response(JSON.stringify({ result: '0x1' }));
    return new Response(JSON.stringify({ok:true,passed:true,logs:'No tests found',durationMs:1}));
  };
  try {
    const result = await runSmartPoc('http://localhost:8787', {address:'0x'+'1'.repeat(40),testCode:'contract PoC {}'});
    assert.equal(result.status, 'error');
    assert.match(result.logs, /SmartPoC/);
    assert.match(result.logs, /SHA-256/);
    assert.equal(result.evidence?.engine, 'foundry');
    assert.equal(result.evidence?.testCount, 0);
  } finally { globalThis.fetch = original; }
});

test('SmartPoC keeps Base RPC retries on Base and records real test counts', async () => {
  const original = globalThis.fetch;
  const urls: string[] = [];
  globalThis.fetch = async (_url, init) => {
    const body = JSON.parse(String(init?.body ?? "{}"));
    // The pre-run balance probe is not a PoC call — do not record its URL.
    if (body.method === 'eth_getBalance') return new Response(JSON.stringify({ result: '0x1' }));
    urls.push(body.rpcUrl);
    return new Response(JSON.stringify({ok:true,passed:true,logs:'[PASS] testProof()\n1 passed; 0 failed',durationMs:2}));
  };
  try {
    const result = await runSmartPoc('http://localhost:8787', {address:'0x'+'1'.repeat(40),testCode:'contract PoC {}',chainId:8453});
    assert.equal(result.status,'passed');
    assert.equal(result.evidence?.testCount,1);
    assert.equal(result.evidence?.chainId,"8453");
    assert.ok(urls[0].includes('base'));
  } finally { globalThis.fetch = original; }
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

test('SmartPoC skips the run when the target native balance is zero', async () => {
  const original = globalThis.fetch;
  let backendCalls = 0;
  globalThis.fetch = async (_url, init) => {
    const body = JSON.parse(String(init?.body ?? "{}"));
    if (body.method === 'eth_getBalance') return new Response(JSON.stringify({ result: '0x0' }));
    backendCalls++;
    return new Response(JSON.stringify({ok:true,passed:true,logs:'1 passed; 0 failed',durationMs:1}));
  };
  try {
    const result = await runSmartPoc('http://localhost:8787', {address:'0x'+'1'.repeat(40),testCode:'contract PoC {}'});
    assert.equal(result.status, 'skipped');
    assert.match(result.logs, /holds 0/);
    assert.equal(backendCalls, 0, 'the backend must not be called for a zero-balance target');
  } finally { globalThis.fetch = original; }
});

test('skipZeroBalance:false forces the run on a zero-balance target', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const body = JSON.parse(String(init?.body ?? "{}"));
    if (body.method === 'eth_getBalance') return new Response(JSON.stringify({ result: '0x0' }));
    return new Response(JSON.stringify({ok:true,passed:true,logs:'1 passed; 0 failed',durationMs:1}));
  };
  try {
    const result = await runSmartPoc('http://localhost:8787', {address:'0x'+'1'.repeat(40),testCode:'contract PoC {}',skipZeroBalance:false});
    assert.equal(result.status, 'passed');
  } finally { globalThis.fetch = original; }
});

test('an RPC outage on the balance probe does NOT skip the run', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const body = JSON.parse(String(init?.body ?? "{}"));
    if (body.method === 'eth_getBalance') throw new Error('network down');
    return new Response(JSON.stringify({ok:true,passed:true,logs:'1 passed; 0 failed',durationMs:1}));
  };
  try {
    const result = await runSmartPoc('http://localhost:8787', {address:'0x'+'1'.repeat(40),testCode:'contract PoC {}'});
    assert.equal(result.status, 'passed');
  } finally { globalThis.fetch = original; }
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
      evidence:{engine:'foundry',startedAt:now,finishedAt:now,target:'0x'+'1'.repeat(40),chainId:'8453',sourceHash:'hash',backendUrl:'http://localhost:8787',rpcUrls:[],testCount:1}},
      'executed source',8453,{url:'https://test.supabase.co',anonKey:'sb_publishable_test',enabled:true});
    assert.equal(result,'saved');
    assert.equal(row?.source,'executed source');
    assert.equal(row?.chain_id,8453);
    assert.match(String(row?.output),/SmartPoC/);
  } finally { globalThis.fetch = original; }
});

test('SmartPoC repairs a compile failure once and records the code actually executed', async () => {
  const original = globalThis.fetch;
  let calls = 0, repairs = 0;
  globalThis.fetch = async (_url, init) => {
    // The pre-run balance probe must not consume a PoC call slot.
    if (JSON.parse(String(init?.body ?? "{}")).method === 'eth_getBalance') return new Response(JSON.stringify({ result: '0x1' }));
    calls++;
    return new Response(JSON.stringify(calls === 1
      ? {ok:true,passed:false,logs:'Compiler run failed: TypeError',durationMs:1}
      : {ok:true,passed:true,logs:'1 passed; 0 failed',durationMs:1}));
  };
  try {
    const result = await runSmartPoc('http://localhost:8787',{address:'0x'+'1'.repeat(40),testCode:'broken',
      repair: async () => { repairs++; return 'fixed'; }});
    assert.equal(result.status,'passed');
    assert.equal(result.executedSource,'fixed');
    assert.equal(repairs,1);
    assert.equal(calls,2);
  } finally { globalThis.fetch = original; }
});


test("a repaired proof is reused only while its original finding input is unchanged", async () => {
  const {pocInputDigest} = await import("./foundry-backend.ts");
  const f = {exploitSolidity:"original",pocCode:"repaired test",pocStatus:"passed",pocRunAt:"2026-10-20",pocOutput:`Finding input SHA3-256: ${pocInputDigest("original")}\n[SmartPoC | Foundry] tests=1`};
  assert.equal(needsSmartPoc(f),false);
  assert.equal(needsSmartPoc({...f,exploitSolidity:"changed"}),true);
});

test('SmartPoC binds the executed source for synchronous UI evidence labels', async () => {
  const { classifyPocEvidence } = await import('./poc-evidence.ts');
  const original = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    if (JSON.parse(String(init?.body ?? "{}")).method === 'eth_getBalance') return new Response(JSON.stringify({ result: '0x1' }));
    return new Response(JSON.stringify({ok:true,passed:true,logs:'[PASS] test_exploit()\n1 passed; 0 failed',durationMs:1}));
  };
  try {
    const code = 'contract PoC { function test_exploit() public {} }';
    const result = await runSmartPoc('http://localhost:8787', {address:'0x'+'1'.repeat(40),testCode:code});
    assert.equal(classifyPocEvidence({code,result}).stage,'reproduced');
    assert.notEqual(classifyPocEvidence({code:code+' // edited',result}).stage,'reproduced');
  } finally { globalThis.fetch = original; }
});
