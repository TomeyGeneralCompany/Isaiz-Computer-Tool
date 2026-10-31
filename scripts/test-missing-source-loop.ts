import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';
const root=await mkdtemp(join(tmpdir(),'missing-source-'));let calls=0;
const server=createServer(async(req,res)=>{let raw='';for await(const c of req)raw+=c;
 const body=JSON.parse(raw);if(calls)assert.match(body.messages.at(-1).content,/path does not exist/);
 calls++;res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify({action:'read_file',path:'nonexistent.sol',query:'',answer:'',offset:calls})}}));});
try {
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
 process.env.AUTOHACK_OLLAMA_URL=`http://127.0.0.1:${(server.address() as any).port}/api/chat`;
 await assert.rejects(runLocalAudit('Inspect source',join(root,'audit.log'),30000,root,'mock',undefined,{maxTurns:80,dynamicAllowance:true,numCtx:4096,numPredict:128}),/repeated missing source path/);
 assert.equal(calls,3);const summary=JSON.parse(await readFile(join(root,'audit.log.summary.json'),'utf8'));
 assert.equal(summary.successfulReads,0);assert.equal(summary.turnAllowance,80);
 console.log('Missing paths receive navigation feedback, no extension credit, and bounded failure PASSED');
}finally{server.closeAllConnections();server.close();await rm(root,{recursive:true,force:true});}


// Regression for the real Qwen failure: it read c63115ff54.py successfully,
 // then dropped one digit and repeated c6315ff54.py after a rejected final.
 // The tool error must provide the exact verified path, without silently
 // substituting a guessed source or weakening the three-strike failure guard.
const recoveryRoot=await mkdtemp(join(tmpdir(),'missing-source-recovery-'));
await writeFile(join(recoveryRoot,'c63115ff54.py'),'def render_87b7476409(value):\\n    return value\\n');
let recoveryCalls=0,recoveryFeedback='';
const recoveryServer=createServer(async(req,res)=>{
  let raw='';for await(const chunk of req)raw+=chunk;
  const body=JSON.parse(raw);
  const i=recoveryCalls++;
  if(i===2)recoveryFeedback=String(body.messages.at(-1)?.content||'');
  const actions=[
    {action:'read_file',path:'c63115ff54.py',query:'',answer:'',offset:0},
    {action:'read_file',path:'c6315ff54.py',query:'',answer:'',offset:0},
    {action:'final',path:'',query:'',answer:'{"ok":true}'},
  ];
  res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify(actions[Math.min(i,2)])}}));
});
try {
  await new Promise<void>(resolve=>recoveryServer.listen(0,'127.0.0.1',resolve));
  process.env.AUTOHACK_OLLAMA_URL=`http://127.0.0.1:${(recoveryServer.address() as any).port}/api/chat`;
  process.env.LOCAL_OLLAMA_TOOL_PROTOCOL='json';
  const answer=await runLocalAudit('Inspect the owned source and return a final result',
    join(recoveryRoot,'audit.log'),30000,recoveryRoot,'mock',undefined,{
      productionWorkflow:true,maxTurns:6,numCtx:8192,numPredict:512,numThreads:4,
      verifyPython:async()=>{throw new Error('No probe requested in missing-path regression');},
    });
  assert.equal(recoveryCalls,3);
  assert.match(recoveryFeedback,/Tool error:/);
  assert.match(recoveryFeedback,/c6315ff54\\.py/);
  assert.match(recoveryFeedback,/Exact successfully read source paths/);
  assert.match(recoveryFeedback,/c63115ff54\\.py/);
  assert.deepEqual(JSON.parse(answer),{ok:true});
  const summary=JSON.parse(await readFile(join(recoveryRoot,'audit.log.summary.json'),'utf8'));
  assert.equal(summary.successfulReads,1);
  console.log('Missing source recovery supplies exact verified paths without inventing evidence PASSED');
}finally {
  recoveryServer.closeAllConnections();recoveryServer.close();
  await rm(recoveryRoot,{recursive:true,force:true});
}
