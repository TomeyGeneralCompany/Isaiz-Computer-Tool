import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,writeFile,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';
const root=await mkdtemp(join(tmpdir(),'audit-context-loop-'));
let turn=0,offset=0;
const spans:Array<{start:number;end:number}>=[];
const server=createServer(async(req,res)=>{
 let raw='';for await(const chunk of req)raw+=chunk;
 const request=JSON.parse(raw);turn++;
 assert.ok(request.messages[0].content.includes('offline source audit'));
 assert.ok(request.messages[1].content.includes('KEEP_THIS_TASK'));
 assert.ok(JSON.stringify(request.messages).length<6000,'History must remain bounded');
 if(turn>1) {
   const last=request.messages.at(-1);
   const output=JSON.parse(JSON.parse(last.content.split('\n')[0].slice('TOOL_RESULT '.length)).output);
   assert.equal(output.start,offset);offset=output.nextOffset;
   assert.ok(offset>output.start);
 }
 const action=turn===31?{action:'final',path:'',query:'',answer:'DONE'}:
   {action:'read_file',path:'large.sol',query:'',answer:'',offset};
 res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify(action)}}));
});
try {
 await writeFile(join(root,'large.sol'),'uint256 public value;\n'.repeat(5000));
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
 const address=server.address();assert.ok(address&&typeof address!=='string');
 process.env.AUTOHACK_OLLAMA_URL=`http://127.0.0.1:${address.port}/api/chat`;
 process.env.LOCAL_OLLAMA_TOOL_PROTOCOL='json';
 const checkpointPath=join(root,'checkpoint.json');
 assert.equal(await runLocalAudit('KEEP_THIS_TASK: inspect the source',join(root,'log'),15000,root,'mock',undefined,
   {maxTurns:35,numCtx:2048,numPredict:128,checkpointPath,onRead:(_path,span)=>spans.push(span)}),'DONE');
 assert.equal(spans.length,30);
 for(let i=1;i<spans.length;i++)assert.equal(spans[i].start,spans[i-1].end);
 const notes=JSON.parse(await readFile(checkpointPath,'utf8'));assert.equal(notes.version,1);assert.equal(notes.notes.length,12);
 console.log('30-turn model loop preserves task, pagination evidence and bounded valid checkpoints PASSED');
} finally {server.closeAllConnections();server.close();await rm(root,{recursive:true,force:true});}
