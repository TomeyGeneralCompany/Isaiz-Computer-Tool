import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {controllerIndexedAuditPrompt} from '../packages/security-solver/src/controller-index-prompt';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';

const paths=Array.from({length:2016},(_,i)=>'source-1/src/services/service_'+String(i).padStart(4,'0')+'.py');
const prompt=controllerIndexedAuditPrompt({program:'Level 6 source audit',
  maxTurns:80,candidates:paths.slice(-3).map(path=>({
    path,risk:40,declarations:['def project(value: str) -> str:']}))});
assert.ok(prompt.length<=2400);
assert.ok(!prompt.includes(paths[0]),'Never pin the entire repository in model context');
const root=await mkdtemp(join(tmpdir(),'lotus-index-prompt-envelope-'));
const saved=process.env.AUTOHACK_OLLAMA_URL;
const server=createServer(async(req,res)=>{
  for await(const _ of req){}
  res.setHeader('Content-Type','application/json');
  res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify({
    action:'final',path:'',query:'',answer:'{"findings":[],"outcome":"no_testable_candidate","reason":"fixture only"}'})},done_reason:'stop'}));
});
try{
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  process.env.AUTOHACK_OLLAMA_URL='http://127.0.0.1:'+(server.address() as any).port+'/api/chat';
  const log=join(root,'audit.log');
  let error='';
  try{
    await runLocalAudit(prompt,log,20000,root,'mock',undefined,{
      numCtx:8192,numPredict:2048,maxTurns:2,
      productionWorkflow:true,dynamicAllowance:false,
      initialSourcePaths:paths,verifyPython:async()=>JSON.stringify({status:'behavior_not_observed'})});
  }catch(e){error=String(e);}
  assert.doesNotMatch(error,/Audit instructions leave no usable context|Audit instructions exceed the context budget/,
    'All 2016 indexed paths must remain outside the fixed instruction envelope');
  const logs=await readFile(log,'utf8');
  assert.match(logs,/\[CONTEXT_BUDGET\]/,'Actual Qwen protocol must allocate space with controller reserve');
  console.log('Level 6 full-index Qwen 8192-context pinned-envelope admission PASSED');
}finally{
  server.closeAllConnections();server.close();
  if(saved===undefined)delete process.env.AUTOHACK_OLLAMA_URL;else process.env.AUTOHACK_OLLAMA_URL=saved;
  await rm(root,{recursive:true,force:true});
}
