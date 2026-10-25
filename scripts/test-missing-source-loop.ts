import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
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
