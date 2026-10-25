import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeAddress, RpcUnavailableError } from './address-fetcher.ts';
import { looksLikeBytecode } from './bytecode.ts';
const address = '0x1111111111111111111111111111111111111111';
function providers(verified: boolean, code: string) {
 const before = globalThis.fetch;
 globalThis.fetch = (async (input, init) => {
  const url = String(input);
  const json = (data: unknown, status=200) => new Response(JSON.stringify(data), {status});
  if (url.includes('sourcify.dev/server/files/any/')) return verified ? json({files:[{name:'Vault.sol',content:'pragma solidity ^0.8.0; contract Vault { function ping() public {} }'}]}) : json({},404);
  if (url.includes('repo.sourcify.dev/contracts/')) return json({output:{abi:[{type:'function',name:'ping',inputs:[],outputs:[],stateMutability:'nonpayable'}]}});
  if (init?.body) {
   const method = JSON.parse(String(init.body)).method;
   return json({result: method === 'eth_getCode' ? code : method === 'eth_getBalance' ? '0x0' : '0x'+'0'.repeat(64)});
  }
  return json({},404);
 }) as typeof fetch;
 return () => { globalThis.fetch=before; };
}
for (const verified of [true,false]) test(`full audit callback follows runtime and ABI enrichment (${verified})`, async () => {
 const restore=providers(verified,'0x00');
 try {
  let calls=0;
  const {report}=await analyzeAddress(address,'ethereum',undefined,{resnetRunner:async code=>{
   calls++; assert.equal(code,'0x00');
   return {modelId:'test',architecture:'upstream-resnet1d-16384-v1',checkpointSha256:'a'.repeat(64),inputBytes:1,processedBytes:1,windows:1,policy:'consecutive-16384-zero-pad-l2-class-max-v1',truncated:false,ranAt:new Date().toISOString(),predictions:['access-control','arithmetic','reentrancy','unchecked-calls','others'].map(label=>({label,score:0.1,threshold:0.5,flagged:false}))};
  }});
  assert.equal(calls,1); assert.equal(report.inventory.bytecodeBytes,1);
  assert.ok(report.inventory.abi); assert.equal(report.inventory.resnetStatus?.status,'ok');
  assert.equal(report.resnet?.processedBytes,1);
 } finally {restore();}
});
test('one byte runtime is bytecode',()=>assert.equal(looksLikeBytecode('0x00'),true));
test('malformed RPC code is an outage',async()=>{
 const restore=providers(false,'0xz');
 try {await assert.rejects(analyzeAddress(address),RpcUnavailableError);} finally{restore();}
});
test('missing Node callback is explicit unavailable',async()=>{
 const restore=providers(false,'0x00');
 try {const {report}=await analyzeAddress(address);assert.equal(report.inventory.resnetStatus?.status,'unavailable');} finally{restore();}
});
test('inference failure is explicit error',async()=>{
 const restore=providers(false,'0x00');
 try {const {report}=await analyzeAddress(address,'ethereum',undefined,{resnetRunner:async()=>{throw Error('inference exploded');}});assert.equal(report.inventory.resnetStatus?.status,'error');} finally{restore();}
});
