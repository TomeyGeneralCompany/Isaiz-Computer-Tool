import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';
const root=await mkdtemp(join(tmpdir(),'audit-stall-'));
let turn=0,mode='stuck',reads=0;
const server=createServer(async(req,res)=>{
 let raw='';for await(const chunk of req)raw+=chunk;
 const request=JSON.parse(raw);turn++;
 if(turn===3)assert.match(JSON.stringify(request.messages),/Repeated inspection action was not executed/);
 const action=mode==='recover' && turn===3 ? {action:'read_file',path:'second.sol',query:'',answer:''}:
   mode==='recover' && turn===4 ? {action:'final',path:'',query:'',answer:'DONE'}:
   {action:'read_file',path:turn===2?'./first.sol':'first.sol',query:'',answer:'',offset:0};
 const message=process.env.LOCAL_OLLAMA_TOOL_PROTOCOL==='native'
   ? action.action==='final'?{role:'assistant',content:'DONE'}:{role:'assistant',content:'',tool_calls:[{function:{name:action.action,arguments:{path:action.path,offset:0}}}]}
   : {role:'assistant',content:JSON.stringify(action)};
 res.end(JSON.stringify({message,load_duration:1000000,prompt_eval_duration:2000000,eval_duration:3000000,total_duration:6000000}));
});
try {
 await writeFile(join(root,'first.sol'),'// first');await writeFile(join(root,'second.sol'),'// second');
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
 process.env.AUTOHACK_OLLAMA_URL=`http://127.0.0.1:${(server.address() as any).port}/api/chat`;
 for(const protocol of ['json','native']) {
  process.env.LOCAL_OLLAMA_TOOL_PROTOCOL=protocol;
  for(mode of ['stuck','recover']) {
   turn=0;reads=0;const log=join(root,protocol+'-'+mode+'.log');
   const run=runLocalAudit('Inspect sources',log,10000,root,'mock',undefined,{maxTurns:10,numCtx:4096,numPredict:128,onRead:()=>reads++});
   if(mode==='stuck') {await assert.rejects(run,/AUDIT_STALLED/);assert.equal(turn,4);assert.equal(reads,1);}
   else {assert.equal(await run,'DONE');assert.equal(reads,2);}
   const text=await readFile(log,'utf8');assert.match(text,/offset=0 end=8 nextOffset=null/);assert.match(text,/"loadMs":1/);assert.match(text,/\[NO_PROGRESS\]/);
  }
 }
 console.log('JSON/native repeated page rejection, bounded stall, corrective recovery and timing diagnostics PASSED');
} finally {server.closeAllConnections();server.close();await rm(root,{recursive:true,force:true});}
