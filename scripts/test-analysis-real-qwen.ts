import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,writeFile,readFile,copyFile,rm} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';

/** Actual Qwen3 4B production ANALYZE request, not an Ollama mock.
 * Must acquire one immutable source-grounded lead and record a model disposition.
 * This test never performs target-network requests or automatic submission.
 */
const root=await mkdtemp(join(tmpdir(),'lotus-real-analyze-'));
const rel='source-1/contracts/Deposit.sol';
const source='// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Deposit {\n'+
  '  uint256 public total;\n'+
  '  function deposit(uint256 amount) external { total += amount; }\n'+
  '  function withdraw(uint256 amount) external { require(total >= amount); total -= amount; }\n'+
  '}\n';
const log=join(root,'analyze.log');
const diagnostic='data/production-workflow-tests/real-analyze-handoff.log';
try{
  await mkdir(dirname(join(root,rel)),{recursive:true});
  await writeFile(join(root,rel),source);
  execFileSync('git',['init','-q'],{cwd:root});
  execFileSync('git',['add','.'],{cwd:root});
  execFileSync('git',['-c','user.name=Test','-c','user.email=test@example.invalid',
    'commit','-qm','Fixture'],{cwd:root});
  // Use the production JSON action schema and the actual Ollama transport.
  process.env.LOCAL_OLLAMA_TOOL_PROTOCOL='json';
  process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX='true';
  process.env.LOCAL_CONTROLLER_OWNED_ACTIONS='true';
  process.env.AUTOHACK_AUTO_SOURCE_PREFETCH='false';
  process.env.LOCAL_MODEL_SOLIDITY_ANALYZE='true';
  process.env.LOCAL_ANALYZE_MODEL_TURNS='4';
  let certificate:unknown;
  await runLocalAudit('Inspect source for security-relevant invariants. '+ 'Historical notes: '+'A'.repeat(2400),
    log,30*60*1000,root,process.env.LOCAL_OLLAMA_MODEL||'qwen3:4b',undefined,{
      productionWorkflow:true,controllerIndex:true,dynamicAllowance:true,
      maxTurns:30,numCtx:8192,numPredict:512,numThreads:4,
      initialSourcePaths:[rel],
      staticLeads:[{path:rel,line:5,rule:'source-review',message:'Assess missing caller authority on deposit'}],
      onAnalysisCertificate:value=>{certificate=value;},
      verifyPython:async()=>JSON.stringify({status:'behavior_not_observed',behavior_observed:false}),
      validateFinal:async()=>null,
    });
  const content=await readFile(log,'utf8');
  assert.match(content,/\[ANALYSIS_LEAD_SELECTED\]/,'Must select actual immutable lead');
  assert.match(content,/\[ANALYSIS_REQUEST_BOUND\]/,'Must send current lead identity and evidence');
  assert.match(content,/\[ANALYSIS_LEAD_(ASSESSED|DEFERRED)\]/,
    'Real Qwen must deliver an accepted source-backed assessment, not just finalization');
  assert.ok(certificate && (certificate as {modelAssessed?:number}).modelAssessed!>=1,
    'Accepted certificate must account for actual model-reviewed lead');
  console.log('Real Qwen ANALYZE lead delivery and stage-lock disposition PASSED');
}finally{
  await mkdir(dirname(diagnostic),{recursive:true});
  try{await copyFile(log,diagnostic);}catch{}
  await rm(root,{recursive:true,force:true});
}
