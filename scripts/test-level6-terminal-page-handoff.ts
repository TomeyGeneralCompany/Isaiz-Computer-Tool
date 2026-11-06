import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {dirname,join} from 'node:path';
import {tmpdir} from 'node:os';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';

const root=await mkdtemp(join(tmpdir(),'lotus-terminal-source-regression-'));
const saved={url:process.env.AUTOHACK_OLLAMA_URL,
  protocol:process.env.LOCAL_OLLAMA_TOOL_PROTOCOL,
  prefetch:process.env.AUTOHACK_AUTO_SOURCE_PREFETCH,
  controller:process.env.LOCAL_CONTROLLER_OWNED_ACTIONS};
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
  const log=join(root,'audit.log');
  await assert.rejects(runLocalAudit('Inspect source',log,20000,root,'mock',undefined,{
    productionWorkflow:true,verifyPython:async()=>JSON.stringify({status:'behavior_not_observed'}),
    maxTurns:12,numCtx:8192,numPredict:256,initialSourcePaths:sourcePaths,
    onRead:(path)=>delivered.push(path)
  }),/12-turn inspection limit|inspection limit/);
  const text=await readFile(log,'utf8');
  assert.ok((text.match(/\[CONTROLLER_READ_REDIRECT\]/g)||[]).length>=8,
    'Repeated completed-page request must redirect to unread authorized source');
  assert.ok(new Set(delivered).size>=9,'Controller must advance through the source queue');
  assert.ok(delivered.filter(path=>path===sourcePaths[0]).length<=2,
    'A previously completed page cannot absorb the entire investigation');
  console.log('Level 6 repeated completed-page recovery and controller handoff PASSED');
} finally {
  server.closeAllConnections();server.close();
  for(const [name,value] of Object.entries({
    AUTOHACK_OLLAMA_URL:saved.url,LOCAL_OLLAMA_TOOL_PROTOCOL:saved.protocol,
    AUTOHACK_AUTO_SOURCE_PREFETCH:saved.prefetch,LOCAL_CONTROLLER_OWNED_ACTIONS:saved.controller
  })){if(value===undefined)delete process.env[name];else process.env[name]=value;}
  await rm(root,{recursive:true,force:true});
}
