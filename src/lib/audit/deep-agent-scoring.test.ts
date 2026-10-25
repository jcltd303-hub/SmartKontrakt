import test from 'node:test';
import assert from 'node:assert/strict';
import { applyConfirmedFindings } from '../../../pipeline-worker/deep-agent.ts';
import { analyzeInput } from './engine.ts';
import { riskScore } from './risk.ts';
import { RESNET_CLASSES } from './resnet-result.ts';
test('deep-agent note-only rescore preserves static dominance and ResNet evidence',()=>{
 const report=analyzeInput('0xff','runtime');
 report.findings=[{...report.findings[0],severity:'high',pocStatus:'passed'}] as typeof report.findings;
 report.resnet={modelId:'fixture',architecture:'resnet',checkpointSha256:'a'.repeat(64),inputBytes:1,truncated:false,ranAt:new Date().toISOString(),predictions:RESNET_CLASSES.map(label=>({label,score:.9,threshold:.5,flagged:true}))};
 report.riskScore=riskScore(report.findings,report.resnet);
 const expected=report.riskScore;
 applyConfirmedFindings(report,[],'review completed');
 assert.equal(report.riskScore,expected);
 assert.ok(report.riskScore>=65);
});
