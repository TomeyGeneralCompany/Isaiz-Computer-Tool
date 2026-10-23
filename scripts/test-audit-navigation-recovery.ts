import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';
const root=await mkdtemp(join(tmpdir(),'audit-navigation-'));
let turn=0,mode='pages',restored=false;
let spans:Array<{path:string;start:number;end:number}>=[];
const server=createServer(async(req,res)=>{
 let raw='';for await(const c of req)raw+=c;
 const request=JSON.parse(raw);turn++;
 let action:any={action:'read_file',path:'large.js',query:'',answer:''};
 if(mode==='pages') {
   if(turn===21)action={action:'final',path:'',query:'',answer:'DONE'};
 } else {
   if(turn===1)action={...action,path:'first.js',offset:0};
   else if(restored)action={action:'final',path:'',query:'',answer:'DONE'};
   else if(!JSON.stringify(request.messages).includes('FIRST_EVIDENCE_MARKER')) {
     restored=true;action={...action,path:'first.js',offset:0};
   } else action={...action,offset:(turn-2)*300};
 }
 const message=process.env.LOCAL_OLLAMA_TOOL_PROTOCOL==='native'
 ? action.action==='final'?{role:'assistant',content:'DONE'}:{role:'assistant',content:'',tool_calls:[{function:{name:action.action,arguments:{path:action.path,...(action.offset===undefined?{}:{offset:action.offset})}}}]}
 : {role:'assistant',content:JSON.stringify(action)};
 res.end(JSON.stringify({message}));
});
try {
 await writeFile(join(root,'large.js'),'const value = 123;\n'.repeat(8000));
 await writeFile(join(root,'first.js'),'// FIRST_EVIDENCE_MARKER');
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
 process.env.AUTOHACK_OLLAMA_URL=`http://127.0.0.1:${(server.address() as any).port}/api/chat`;
 for(const protocol of ['json','native']) {
  process.env.LOCAL_OLLAMA_TOOL_PROTOCOL=protocol;
  for(mode of ['pages','reread']) {
   turn=0;restored=false;spans=[];
   const log=join(root,protocol+'-'+mode+'.log');
   assert.equal(await runLocalAudit('Inspect these owned fixtures',log,20000,root,'mock',undefined,
    {maxTurns:25,numCtx:2048,numPredict:128,onRead:(path,span)=>spans.push({path,...span})}),'DONE');
   const text=await readFile(log,'utf8');
   if(mode==='pages') {
    assert.equal(spans.length,20);
    for(let i=1;i<spans.length;i++)assert.equal(spans[i].start,spans[i-1].end,'Repeated omitted offset must advance, never silently reread');
    assert.match(text,/PAGE_ADVANCE/);
   } else {
    assert.ok(restored);assert.equal(spans.filter(s=>s.path==='first.js').length,2);
    assert.match(text,/CONTEXT_REREAD/);
   }
  }
 }
 console.log('JSON/native cursor recovery and re-reading evidence after context eviction PASSED');
} finally {server.closeAllConnections();server.close();await rm(root,{recursive:true,force:true});}
