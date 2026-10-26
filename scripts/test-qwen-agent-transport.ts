import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {postQwenAgentJson} from '../packages/security-solver/src/qwen-agent-transport';
const server=createServer();let mode='ok',calls=0;
server.on('request',async(req,res)=>{
 let body='';for await(const chunk of req)body+=chunk;
 const request=JSON.parse(body);calls++;
 assert.equal(request.options.num_thread,4);assert.equal(request.options.num_ctx,8192);
 assert.equal(request.think,false);assert.equal(request.tools,undefined);
 assert.ok(JSON.stringify(request.messages).includes('audit_action'));
 if(mode==='hang')return;
 const tool='<tool_call>\n'+JSON.stringify({name:'audit_action',arguments:{action:'read_file',path:'owned.py',query:'',answer:''}})+'\n</tool_call>';
 res.end(JSON.stringify({message:{role:'assistant',content:mode==='multiple'?tool+'\n'+tool:tool},eval_count:42}));
});
await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
const url=`http://127.0.0.1:${(server.address() as any).port}/api/chat`;
const payload={model:'qwen3:4b',options:{num_ctx:8192,num_thread:4,num_predict:1024},messages:[{role:'system',content:'Owned test'},{role:'user',content:'Read owned.py'}],format:{type:'object',properties:{action:{type:'string',enum:['read_file']},path:{type:'string'},query:{type:'string'},answer:{type:'string'}},required:['action','path','query','answer']}};
try {
 const result=await postQwenAgentJson(url,payload,AbortSignal.timeout(30000));
 assert.equal(JSON.parse(result.message.content).path,'owned.py');assert.equal(result.eval_count,42);
 mode='multiple';await assert.rejects(postQwenAgentJson(url,payload,AbortSignal.timeout(30000)),/exactly one/);
 await assert.rejects(postQwenAgentJson('https://example.com/api/chat',payload,AbortSignal.timeout(30000)),/local Ollama/);
 mode='hang';const controller=new AbortController();const request=postQwenAgentJson(url,payload,controller.signal);
 const timer=setInterval(()=>{if(calls>=3)controller.abort();},25);
 try{await assert.rejects(request,/cancelled/);}finally{clearInterval(timer);}
 mode='ok';await postQwenAgentJson(url,payload,AbortSignal.timeout(30000));
 console.log('Qwen-Agent real package formatting/parsing, local-only endpoint, multiple-call rejection, cancellation and gate release PASSED');
} finally {server.closeAllConnections();server.close();}
