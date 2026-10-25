import test from 'node:test';
import assert from 'node:assert/strict';
import { inferAllBytes } from './all-bytes.ts';
import { CLASSES } from './runtime.ts';
const manifest={modelId:'real-model',architecture:'upstream-resnet1d-16384-v1',checkpointSha256:'a'.repeat(64),classes:[...CLASSES],thresholds:[.5,.5,.5,.5,.5]};
test('all bytes including partial tail beyond 128KiB reach inference',async()=>{
 let calls=0; const r=await inferAllBytes('0x'+'00'.repeat(131072)+'ff',async input=>{calls++;assert.equal(input.length,16384);return [input[0],0,0,0,0];},manifest);
 assert.equal(calls,9);assert.equal(r.processedBytes,131073);assert.equal(r.windows,9);assert.equal(r.predictions?.[0].score,1);assert.equal(r.predictions?.[0].flagged,true);
});
test('normalizes each window independently and max pools classes',async()=>{
 let i=0;const r=await inferAllBytes('03'.repeat(16384)+'04',async input=>{assert.equal(input[0],i===0?1/128:1);return i++===0?[.7,.1,.2,.3,.4]:[.1,.8,.3,.2,.1];},manifest);
 assert.deepEqual(r.predictions?.map(p=>p.score),[.7,.8,.3,.3,.4]);
});
test('rejects malformed inputs and invalid outputs',async()=>{
 for(const s of ['', '0x','0x123','zz'])await assert.rejects(()=>inferAllBytes(s,async()=>[0,0,0,0,0],manifest));
 for(const p of [[0],[NaN,0,0,0,0],[1.1,0,0,0,0]])await assert.rejects(()=>inferAllBytes('00',async()=>p,manifest));
});
