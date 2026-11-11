import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {dirname,join} from 'node:path';
import {tmpdir} from 'node:os';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';

const root=await mkdtemp(join(tmpdir(),'lotus-indexed-nonprogress-regression-'));
const saved={url:process.env.AUTOHACK_OLLAMA_URL,
  protocol:process.env.LOCAL_OLLAMA_TOOL_PROTOCOL,
  prefetch:process.env.AUTOHACK_AUTO_SOURCE_PREFETCH,
  controller:process.env.LOCAL_CONTROLLER_OWNED_ACTIONS,
  fullIndex:process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX};
const sourcePaths=Array.from({length:16},(_,i)=>
  'source-1/src/services/service_'+String(i).padStart(4,'0')+'.py');
const delivered:string[]=[];
let generations=0;
const server=createServer(async(req,res)=>{
  for await(const _chunk of req){} // Mock fixed model disregards controller feedback.
  generations++;
  res.end(JSON.stringify({message:{role:'assistant',
    content:JSON.stringify({action:'read_file',path:sourcePaths[0],query:'',answer:'',offset:0})}}));
});
try {
  for(const path of sourcePaths){
    const full=join(root,path);
    await mkdir(dirname(full),{recursive:true});
    await writeFile(full,'def project(value: str) -> str:\n    return "<p>" + value + "</p>"\n');
  }
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  process.env.AUTOHACK_OLLAMA_URL='http://127.0.0.1:'+(server.address() as any).port+'/api/chat';
  process.env.LOCAL_OLLAMA_TOOL_PROTOCOL='json';
  process.env.AUTOHACK_AUTO_SOURCE_PREFETCH='false';
  process.env.LOCAL_CONTROLLER_OWNED_ACTIONS='false';
  process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX='true';
  const log=join(root,'audit.log');
  await assert.rejects(runLocalAudit('Inspect source',log,20000,root,'mock',undefined,{
    productionWorkflow:true,verifyPython:async()=>JSON.stringify({status:'behavior_not_observed'}),
    maxTurns:80,numCtx:8192,numPredict:256,initialSourcePaths:sourcePaths,
    onRead:(path)=>delivered.push(path)
  }),/Local audit reached its 80-turn inspection limit/);
  const text=await readFile(log,'utf8');
  assert.equal((text.match(/\[CONTROLLER_READ_REDIRECT\]/g)||[]).length,0,
    'Full-index mode must never redirect a completed read to unrelated sources');
  assert.ok(text.includes('[INDEXED_SOURCE_TO_EVIDENCE_HANDOFF]'), 'Exhausted index must offer an evidence/probe transition rather than fatal AUDIT_STALLED');
  assert.ok(!text.includes('AUDIT_STALLED: indexed source'), 'Old fatal index stall must not recur');
  assert.ok(generations<=80,'Fixed model cannot advance to probes, but run must respect turn allowance');
  assert.ok(delivered.length<=2,'Only the actual source and optional context recovery may be read');
  // Production controller authority: even when no executable probe exists,
  // Qwen must not be called to choose a new source or transition. The
  // controller reads exactly once and exposes an explicit diagnostic.
  const ownedPath='source-1/src/services/no_candidate.py';
  const ownedFull=join(root,ownedPath);
  await mkdir(dirname(ownedFull),{recursive:true});
  await writeFile(ownedFull,'# No callable function or supported probe here\\n');
  process.env.LOCAL_CONTROLLER_OWNED_ACTIONS='true';
  const beforeOwnedGenerations=generations;
  const ownedReads:string[]=[];
  const ownedLog=join(root,'controller-owned.log');
  const completed=await runLocalAudit('Inspect source',ownedLog,20000,root,'mock',undefined,{
    productionWorkflow:true,verifyPython:async()=>JSON.stringify({status:'behavior_not_observed'}),
    maxTurns:8,numCtx:8192,numPredict:256,initialSourcePaths:[ownedPath],
    onRead:path=>ownedReads.push(path)
  });
  const disposition=JSON.parse(completed);
  assert.equal(disposition.outcome,'no_testable_candidate');
  assert.deepEqual(disposition.findings,[]);
  assert.match(disposition.reason,/no source-grounded executable security scenario/i);
  assert.equal(generations,beforeOwnedGenerations,
    'Controller-owned investigation must not ask Qwen to choose sources or transitions');
  assert.deepEqual(ownedReads,[ownedPath],
    'Controller must read the ranked file once and retain its cursor without model navigation');
  // The verified-case handoff is an authorized semantic assessment, not
  // source navigation. Prevent the previous contradictory guard from returning.
  const {InvestigationWorkflow}=await import('../packages/security-solver/src/investigation-workflow');
  const verified=new InvestigationWorkflow();
  const caseId='a'.repeat(64);
  verified.observe({action:'verify_source',path:ownedPath,query:'Demo.render',
    answer:'html_reflection'} as any,JSON.stringify({status:'behavior_observed',
    behavior_observed:true,caseId,evidenceFile:'.audit-evidence/verified.json'}));
  assert.equal(verified.focusVerifiedEvidence(caseId),true);
  assert.deepEqual((await verified.constraints()).action,['final'],
    'Controller-verified reproduction must permit a final semantic assessment');
  const runnerSource=await readFile(new URL('../packages/security-solver/src/local-ollama-runner.ts',import.meta.url),'utf8');
  assert.ok(runnerSource.includes("permitted.every(action=>action==='final') &&\\n          !snapshot.pending;"),
    'No-navigation guard must permit the verified-case final handoff');
  assert.ok(!runnerSource.includes('!snapshot.pending && !snapshot.verifiedEvidenceFocus'),
    'Verified evidence must not disqualify a final handoff');
  console.log('Controller-owned indexed source read and zero Qwen navigation calls PASSED');
  console.log('Indexed controller preserves source evidence and offers probe handoff under uncooperative model PASSED');
} finally {
  server.closeAllConnections();server.close();
  for(const [name,value] of Object.entries({
    AUTOHACK_OLLAMA_URL:saved.url,LOCAL_OLLAMA_TOOL_PROTOCOL:saved.protocol,
    AUTOHACK_AUTO_SOURCE_PREFETCH:saved.prefetch,LOCAL_CONTROLLER_OWNED_ACTIONS:saved.controller,LOCAL_CONTROLLER_FULL_SOURCE_INDEX:saved.fullIndex
  })){if(value===undefined)delete process.env[name];else process.env[name]=value;}
  await rm(root,{recursive:true,force:true});
}
