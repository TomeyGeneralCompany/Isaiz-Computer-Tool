import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp,writeFile,readFile,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runLocalAudit } from '../packages/security-solver/src/local-ollama-runner';
const root=await mkdtemp(join(tmpdir(),'progress-controller-'));
let calls=0, mode='extend',offset=0;
const server=createServer(async(req,res)=>{
 let raw='';for await(const part of req)raw+=part;
 const input=JSON.parse(raw);calls++;
 if(mode==='extend' && calls>1) {
   const output=JSON.parse(JSON.parse(input.messages.at(-1).content.split('\n')[0].slice(12)).output);
   offset=output.nextOffset;
 }
 let action:any={action:'read_file',path:'sample.py',query:'',answer:'',offset};
 if(mode==='extend' && calls===86)action={action:'final',path:'',query:'',answer:'DONE'};
 if(mode!=='extend' && calls>1)action={action:'final',path:'',query:'',answer:mode==='recover'&&calls===4?'DONE':''};
 res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify(action)}}));
});
try {
 await writeFile(join(root,'sample.py'),'value = 1\n'.repeat(30000));
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
 process.env.AUTOHACK_OLLAMA_URL=`http://127.0.0.1:${(server.address() as any).port}/api/chat`;
 process.env.LOCAL_OLLAMA_TOOL_PROTOCOL='json';
 const limits={maxTurns:80,numCtx:4096,numPredict:128,dynamicAllowance:true};
 assert.equal(await runLocalAudit('Read sample.py',join(root,'extended.log'),30000,root,'mock',undefined,limits),'DONE');
 assert.equal(calls,86);
 const summary=JSON.parse(await readFile(join(root,'extended.log.summary.json'),'utf8'));
 assert.equal(summary.turnAllowance,120);assert.equal(summary.turns,86);
 assert.match(await readFile(join(root,'extended.log'),'utf8'),/ALLOWANCE_EXTENDED/);
 mode='recover';calls=0;offset=0;
 assert.equal(await runLocalAudit('Read sample.py',join(root,'recover.log'),30000,root,'mock',undefined,limits),'DONE');
 assert.equal(calls,4);
 mode='empty';calls=0;
 await assert.rejects(runLocalAudit('Read sample.py',join(root,'empty.log'),30000,root,'mock',undefined,limits),/after two corrective retries/);
 assert.equal(calls,4);
 assert.match(JSON.parse(await readFile(join(root,'empty.log.summary.json'),'utf8')).stoppingReason,/empty final/);
 console.log('Actual controller extends beyond 80 turns; empty finals recover or fail explicitly PASSED');
} finally {server.closeAllConnections();server.close();await rm(root,{recursive:true,force:true});}
