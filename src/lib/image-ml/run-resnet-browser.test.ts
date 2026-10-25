import test from 'node:test';
import assert from 'node:assert/strict';
import { runResnetBrowser } from './run-resnet-browser.ts';

test('browser audits queue and reuse one worker; failure resets it', async () => {
 const originalWindow=globalThis.window, originalWorker=globalThis.Worker;
 let constructed=0, active=0, peak=0, fail=false;
 class FakeWorker {
  onmessage: ((event: {data:unknown})=>void) | null=null;
  onerror: unknown=null;
  constructor(){constructed++;}
  terminate(){}
  postMessage(message:{bytecode:string;allBytes:boolean}) {
   assert.equal(message.allBytes,true); active++;peak=Math.max(peak,active);
   setTimeout(()=>{
    active--;
    if(fail){this.onmessage?.({data:{ok:false,error:'bad runtime'}});return;}
    this.onmessage?.({data:{ok:true,result:{modelId:'fake',architecture:'upstream-resnet1d-16384-v1',checkpointSha256:'a'.repeat(64),predictions:['access-control','arithmetic','reentrancy','unchecked-calls','others'].map(label=>({label,score:0.1,threshold:0.5,flagged:false})),inputBytes:1,processedBytes:1,windows:1,policy:'consecutive-16384-zero-pad-l2-class-max-v1',truncated:false,ranAt:new Date().toISOString()}}});
   },0);
  }
 }
 Object.assign(globalThis,{window:{location:{hostname:'example.test',pathname:'/',origin:'https://example.test'}},Worker:FakeWorker});
 try {
  const results=await Promise.all([runResnetBrowser('0x00'),runResnetBrowser('0xff')]);
  assert.ok(results.every(Boolean)); assert.equal(constructed,1); assert.equal(peak,1);
  fail=true; await assert.rejects(runResnetBrowser('0x00'),/bad runtime/);
  fail=false; assert.ok(await runResnetBrowser('0x00'));assert.equal(constructed,2);
 } finally { Object.assign(globalThis,{window:originalWindow,Worker:originalWorker}); }
});
