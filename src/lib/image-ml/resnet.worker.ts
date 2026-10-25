import * as ort from 'onnxruntime-web/wasm';
import wasmUrl from 'onnxruntime-web/ort-wasm-simd-threaded.wasm?url';
import { download, loadResnet, prepareSequence, runtimeAssetUrl } from './resnet';
import { inferAllBytes } from './all-bytes';
let cached:{url:string;promise:Promise<{manifest:Awaited<ReturnType<typeof loadResnet>>['manifest'];session:ort.InferenceSession}>}|undefined;
async function getModel(url:string){
 if(cached?.url===url)return cached.promise;
 const promise=(async()=>{
  const [{manifest,bytes},wasmBytes]=await Promise.all([loadResnet(url),download(runtimeAssetUrl(wasmUrl,url),20*1024*1024)]);
  ort.env.wasm.numThreads=1;ort.env.wasm.proxy=false;ort.env.wasm.wasmBinary=wasmBytes;
  const session=await ort.InferenceSession.create(bytes,{executionProviders:['wasm']});return {manifest,session};
 })();cached={url,promise};
 try{return await promise;}catch(error){if(cached?.promise===promise)cached=undefined;throw error;}
}
let queue=Promise.resolve();
self.onmessage=(event:MessageEvent<{id?:number;bytecode:string;modelUrl:string;allBytes?:boolean}>)=>{
 queue=queue.then(async()=>{
  const started=performance.now();
  try{
   const {manifest,session}=await getModel(event.data.modelUrl);const loaded=performance.now();
   const predict=async(input:Float32Array)=>{
    const tensor=new ort.Tensor('float32',input,[1,1,16384]);
    try{
     const output=await session.run({bytecode:tensor});
     try{return Array.from(output.probabilities.data as Float32Array);}
     finally{for(const value of Object.values(output))value.dispose();}
    }finally{tensor.dispose();}
   };
   // Explicit legacy path preserves published prefix-checkpoint parity fixtures.
   const result=event.data.allBytes?await inferAllBytes(event.data.bytecode,predict,manifest):null;
   const scores=result?result.predictions.map(p=>p.score):await predict(prepareSequence(event.data.bytecode));
   if(scores.length!==5||scores.some(v=>!Number.isFinite(v)||v<0||v>1))throw new Error('Invalid ResNet output.');
   self.postMessage({id:event.data.id,ok:true,modelId:manifest.modelId,architecture:manifest.architecture,checkpointSha256:manifest.checkpointSha256,training:manifest.training,evaluation:manifest.evaluation,result,
    timing:{loadMs:loaded-started,inferenceMs:performance.now()-loaded},
    predictions:manifest.classes.map((label,i)=>({label,score:scores[i],threshold:manifest.thresholds[i],flagged:scores[i]>=manifest.thresholds[i]}))});
  }catch(error){self.postMessage({id:event.data.id,ok:false,error:error instanceof Error?error.message:'ResNet could not run.'});}
 });
};
