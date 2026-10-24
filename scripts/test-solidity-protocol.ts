import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';
const root=await mkdtemp(join(tmpdir(),'solidity-protocol-'));
const sequence={constructorArgs:['5'],steps:[{operation:'send',function:'set(uint256)',args:['7']},{operation:'call',function:'value()',args:[],expect:'7'}]};
let turn=0,invocations=0;
const server=createServer(async(req,res)=>{
  let raw='';for await(const chunk of req)raw+=chunk;
  const request=JSON.parse(raw);turn++;
  const structured=process.env.LOCAL_OLLAMA_TOOL_PROTOCOL==='json';
  if(structured) {
    assert.ok(request.format.properties.sequence.properties.steps,'Full sequence schema remains enforced');
    assert.ok(!request.messages[0].content.includes('"anyOf"'),'Do not duplicate the full response schema in instructions');
  }
  const name=turn===1?'read_file':'verify_source';
  const args=turn===1?{path:'Store.sol'}:{path:'Store.sol',query:'Store.set',kind:'solidity_sequence',sequence:turn===2?{...sequence,rpcUrl:'invalid'}:sequence};
  if(turn===3)assert.match(request.messages.at(-1).content,/Tool error/);
  if(turn===4)assert.match(request.messages.at(-1).content,/behavior_not_observed/);
  res.setHeader('Content-Type','application/json');
  res.end(JSON.stringify({message:turn===4?{role:'assistant',content:structured?JSON.stringify({action:'final',path:'',query:'',answer:'DONE'}):'DONE'}:
    {role:'assistant',content:structured?JSON.stringify({action:name,path:args.path,query:args.query||'',answer:args.kind||'',...(turn>1?{sequence:args.sequence}:{})}):'',
    ...(structured?{}:{tool_calls:[{function:{name,arguments:args}}]})}}));
});
try {
  await writeFile(join(root,'Store.sol'),'contract Store {}');
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  const address=server.address();assert.ok(address&&typeof address!=='string');
  process.env.AUTOHACK_OLLAMA_URL=`http://127.0.0.1:${address.port}/api/chat`;
  for(const protocol of ['json','native']) {
    process.env.LOCAL_OLLAMA_TOOL_PROTOCOL=protocol;turn=0;
    assert.equal(await runLocalAudit('Test local Solidity',join(root,protocol+'.log'),10000,root,'mock',undefined,{
      maxTurns:5,verifyPython:async(path,fn,kind,received)=>{
        invocations++;assert.equal(path,'Store.sol');assert.equal(fn,'Store.set');assert.equal(kind,'solidity_sequence');
        assert.deepEqual(received,sequence);return JSON.stringify({status:'behavior_not_observed'});
      }
    }),'DONE');
  }
  assert.equal(invocations,2,'Invalid sequences must not reach the executor');
  console.log('JSON/native Solidity sequence forwarding and invalid-sequence rejection PASSED');
} finally {server.closeAllConnections();server.close();await rm(root,{recursive:true,force:true});}
