import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';
const root=await mkdtemp(join(tmpdir(),'native-batch-'));let turns=0,reads=0;
const call={function:{name:'read_file',arguments:{path:'source.sol'}}};
const server=createServer(async(req,res)=>{
 let raw='';for await(const c of req)raw+=c;const request=JSON.parse(raw);turns++;
 if(turns===2)assert.match(request.messages.at(-1).content,/previous batch was not executed/);
 const message=turns===1?{role:'assistant',content:'',tool_calls:Array(8).fill(call)}:
   turns===2?{role:'assistant',content:'',tool_calls:[call]}:{role:'assistant',content:'DONE'};
 res.end(JSON.stringify({message}));
});
try {
 await writeFile(join(root,'source.sol'),'// data\n'.repeat(10000));
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const addr=server.address() as any;
 process.env.AUTOHACK_OLLAMA_URL=`http://127.0.0.1:${addr.port}/api/chat`;process.env.LOCAL_OLLAMA_TOOL_PROTOCOL='native';
 assert.equal(await runLocalAudit('Inspect source',join(root,'log'),10000,root,'mock',undefined,{numCtx:4096,numPredict:1024,maxTurns:4,onRead:()=>reads++}),'DONE');
 assert.equal(reads,1);console.log('Native batch recovery executes one read without overflowing context PASSED');
} finally {server.closeAllConnections();server.close();await rm(root,{recursive:true,force:true});}
