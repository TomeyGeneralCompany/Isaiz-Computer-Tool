import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {postOllamaJson} from '../packages/core/src/ollama-http';
const root=await mkdtemp(join(tmpdir(),'ollama-gate-'));process.env.PROJECT_ROOT=root;
let active=0,maxActive=0,requests=0;
const server=createServer(async(req,res)=>{
 for await(const _ of req){}requests++;active++;maxActive=Math.max(maxActive,active);
 setTimeout(()=>{active--;res.end('{"message":{"content":"ok"}}');},80);
});
let holder:ReturnType<typeof spawn>|undefined;
try {
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const url=`http://127.0.0.1:${(server.address() as any).port}/api/chat`;
 await Promise.all([1,2,3].map(()=>postOllamaJson(url,{},AbortSignal.timeout(5000))));assert.equal(maxActive,1);
 holder=spawn('python3',['-c',"import fcntl,sys; f=open(sys.argv[1],'a'); fcntl.flock(f,fcntl.LOCK_EX); print('ready',flush=True); sys.stdin.read()",join(root,'data/ollama-inference.lock')]);
 await new Promise<void>((resolve,reject)=>{holder!.stdout!.once('data',()=>resolve());holder!.once('error',reject);});
 const before=requests;
 await assert.rejects(postOllamaJson(url,{},AbortSignal.timeout(100)),e=>e instanceof Error&&e.name==='AbortError');assert.equal(requests,before,'Cancelled queued request must not reach HTTP server');
 const pending=postOllamaJson(url,{},AbortSignal.timeout(5000));
 const exit=new Promise<void>(r=>holder!.once('close',()=>r()));holder.kill('SIGKILL');await exit;
 const result:any=await pending;assert.equal(result.message.content,'ok');assert.ok(result.client_queue_ms>=0);
 console.log('Shared Python/TypeScript inference gate: serialization, queued cancellation and killed-owner recovery PASSED');
} finally {holder?.kill();server.closeAllConnections();server.close();await rm(root,{recursive:true,force:true});}
