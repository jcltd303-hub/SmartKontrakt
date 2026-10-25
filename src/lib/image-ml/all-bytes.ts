import { CLASSES } from './runtime.ts';
import type { ResnetResult } from '../audit/resnet-result.ts';
export const FULL_BYTE_POLICY='consecutive-16384-zero-pad-l2-class-max-v1';
/** Fixed tensor memory, no window cap. Max pooling is experimental with prefix-calibrated thresholds. */
export async function inferAllBytes(
 bytecode:string,
 predict:(input:Float32Array)=>Promise<number[]>,
 manifest:{modelId:string;architecture:string;checkpointSha256:string;classes:string[];thresholds:number[]},
):Promise<ResnetResult>{
 const hex=bytecode.trim().replace(/^0x/i,'');
 if(!hex||hex.length%2||!/^[a-f\d]+$/i.test(hex))throw new Error('ResNet requires complete non-empty hexadecimal bytecode.');
 if(JSON.stringify(manifest.classes)!==JSON.stringify(CLASSES)||manifest.thresholds.length!==5||manifest.thresholds.some(t=>!Number.isFinite(t)||t<0||t>1))throw new Error('Invalid ResNet classes or thresholds.');
 const scores=Array<number>(5).fill(0);let windows=0;
 for(let offset=0;offset<hex.length;offset+=32768){
  const input=new Float32Array(16384),length=Math.min(16384,(hex.length-offset)/2);let squares=0;
  for(let i=0;i<length;i++){const v=parseInt(hex.slice(offset+i*2,offset+i*2+2),16);input[i]=v;squares+=v*v;}
  const norm=Math.sqrt(squares);if(norm)for(let i=0;i<length;i++)input[i]/=norm;
  const next=await predict(input);
  if(next.length!==5||next.some(v=>!Number.isFinite(v)||v<0||v>1))throw new Error('Invalid ResNet output.');
  next.forEach((v,i)=>{scores[i]=Math.max(scores[i],v);});windows++;
 }
 return {modelId:manifest.modelId,architecture:manifest.architecture,checkpointSha256:manifest.checkpointSha256,inputBytes:hex.length/2,processedBytes:hex.length/2,windows,policy:FULL_BYTE_POLICY,truncated:false,ranAt:new Date().toISOString(),predictions:manifest.classes.map((label,i)=>({label,score:scores[i],threshold:manifest.thresholds[i],flagged:scores[i]>=manifest.thresholds[i]}))};
}
