import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {postOllamaChat} from '../packages/core/src/ollama-chat';
import {acquireOllamaGate} from '../packages/core/src/ollama-gate';
let mode='stream',requests=0;
const server=createServer(async(req,res)=>{
  let body='';for await(const chunk of req)body+=chunk;
  assert.equal(JSON.parse(body).stream,true);requests++;
  if(mode==='silent')return;
  if(mode==='http'){res.writeHead(503);res.end('SECRET');return;}
  if(mode==='json'){res.end(JSON.stringify({message:{role:'assistant',content:'compatibility'},done:true}));return;}
  if(mode==='badjson'){res.end('SECRET');return;}
  res.writeHead(200,{'Content-Type':'application/x-ndjson'});
  if(mode==='truncated'){res.end('{"message":{"content":"unfinished"},"done":false}\n');return;}
  if(mode==='malformed'){res.end('SECRET\n');return;}
  if(mode==='large'){res.end('x'.repeat(1048577));return;}
  if(mode==='utf8'){
    const data=Buffer.from(JSON.stringify({message:{content:'🦁'},done:true})+'\n');
    const split=data.indexOf(Buffer.from('🦁'))+2;res.write(data.subarray(0,split));res.end(data.subarray(split));return;
  }
  let count=0;
  const activeMode=mode;
  const timer=setInterval(()=>{
    count++;
    if(activeMode==='empty'){res.write('{"message":{"content":""},"done":false}\n');return;}
    if(count<8){res.write(JSON.stringify({message:count%2?{thinking:'t'}:{content:'x'},done:false})+'\n');return;}
    if(activeMode==='endless'){res.write('{"message":{"content":"x"},"done":false}\n');return;}
    res.end(JSON.stringify({message:{content:'!',tool_calls:[{function:{name:'read_file',arguments:{path:'owned.py'}}}]},done:true,eval_count:8,done_reason:'stop'})+'\n');
  },30);
  res.on('close',()=>clearInterval(timer));
});
await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
const url=`http://127.0.0.1:${(server.address() as any).port}/api/chat`;
const call=(timeout=3000,options={})=>postOllamaChat(url,{model:'owned'},AbortSignal.timeout(timeout),{idleTimeoutMs:150,...options});
try {
  let updates=0;const result=await call(3000,{onProgress:()=>updates++});
  assert.equal(result.message.content,'xxx!');assert.equal(result.message.thinking,'tttt');
  assert.equal(result.message.tool_calls[0].function.name,'read_file');assert.equal(result.eval_count,8);assert(updates>=8);
  const release=await acquireOllamaGate(AbortSignal.timeout(3000));
  const pending=call();setTimeout(()=>void release(),220);
  assert((await pending).client_queue_ms>=200,'Queue wait must not consume the 150ms inactivity budget');
  const held=await acquireOllamaGate(AbortSignal.timeout(3000));const before=requests;
  await assert.rejects(call(50));assert.equal(requests,before,'Cancelled queued calls never dispatch');await held();
  for(const type of ['silent','empty']){mode=type;await assert.rejects(call(),/inactivity deadline/);}
  mode='endless';await assert.rejects(call(170),'Overall cancellation must terminate even active generation');
  for(const type of ['truncated','malformed','badjson','http','large']){
    mode=type;await assert.rejects(call(),error=>error instanceof Error&&!error.message.includes('SECRET'));
  }
  mode='utf8';assert.equal((await call()).message.content,'🦁');
  mode='json';assert.equal((await call()).message.content,'compatibility');
  mode='stream';assert.equal((await call()).done_reason,'stop','Gate must recover after every failed request');
  console.log('Streaming progress, queued deadlines, silent stalls, empty frames, cancellation, completion, UTF-8, tool calls and bounds PASSED');
} finally {server.closeAllConnections();server.close();}
