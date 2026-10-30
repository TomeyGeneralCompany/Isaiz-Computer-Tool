import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createServer } from 'node:http';
import { SoliditySourceIndex } from '../packages/security-solver/src/solidity-source-index';
import { SourceReads } from '../packages/security-solver/src/source-inspection';
import { runLocalAudit } from '../packages/security-solver/src/local-ollama-runner';
const root=await mkdtemp(join(tmpdir(),'solidity-index-'));
const server=createServer();
try {
  const base='pragma solidity ^0.8.20; contract Base { mapping(address=>uint) internal balances; bool locked; modifier nonReentrant() { require(!locked); locked=true; _; locked=false; } function helper(uint x) internal pure returns(uint) { return x; } }';
  const source=`// Unicode before declarations: café 🦆\npragma solidity ^0.8.20;
import {Base as Parent} from "./Base.sol";
contract Vault is Parent {
 constructor(uint x) { balances[msg.sender]=x; }
 function withdraw(uint x) external nonReentrant { balances[msg.sender]-=helper(x); }
 function withdraw() external { balances[msg.sender]=0; }
 function huge() external {\n${'balances[msg.sender]++;\n'.repeat(300)}}
}`;
  await writeFile(join(root,'Base.sol'),base);await writeFile(join(root,'Vault.sol'),source);
  const index=new SoliditySourceIndex(root);
  assert.equal(await index.hasFunction(join(root,'Vault.sol'),'Vault.withdraw'),true);
  assert.equal(await index.hasFunction(join(root,'Vault.sol'),'Vault.constructor'),true);
  assert.equal(await index.hasFunction(join(root,'Vault.sol'),'Vault.function'),false,'placeholder is not a declared method');
  assert.equal(await index.hasFunction(join(root,'Vault.sol'),'Vault.randomMethod'),false,'invented function is not a declared method');
  const outline=await index.outline(join(root,'Vault.sol'),0,8000);
  const functions=outline.items.filter(x=>x.kind==='FunctionDefinition');
  assert.equal(functions.length,4);assert.ok(functions.some(x=>x.name==='constructor'));
  const withdraw=functions.find(x=>String(x.signature).includes('withdraw(uint'))!;
  assert.equal(source.slice(Number(withdraw.start),Number(withdraw.end)).startsWith('function withdraw(uint'),true,'Ranges must use UTF-16 even after emoji');
  await assert.rejects(index.context(join(root,'Vault.sol'),'Vault.withdraw',0,8000),/overloaded/);
  const bundle=await index.context(join(root,'Vault.sol'),String(withdraw.id),0,8000);
  assert.equal(bundle.nextOffset,null);
  assert.ok(bundle.excerpts.some(x=>x.path==='Base.sol'&&x.text.includes('modifier nonReentrant')));
  assert.ok(bundle.excerpts.some(x=>x.path==='Base.sol'&&x.text.includes('mapping(address')));
  assert.ok(bundle.excerpts.some(x=>x.text.includes('import {Base as Parent}')));
  assert.ok(bundle.helpers.some(x=>x.name==='Base.helper'));
  for(const excerpt of bundle.excerpts)assert.equal(excerpt.text,(excerpt.path==='Base.sol'?base:source).slice(excerpt.start,excerpt.end));
  const huge=functions.find(x=>x.name==='huge')!;
  let offset:number|null=0, turns=0;const evidence=new SourceReads();
  while(offset!==null) {
    const result=await index.context(join(root,'Vault.sol'),String(huge.id),offset,1500);
    assert.ok(JSON.stringify(result).length<=1500);
    for(const e of result.excerpts){assert.equal(e.text,(e.path==='Base.sol'?base:source).slice(e.start,e.end));evidence.add(e.path,e);}
    if(turns++===0)assert.equal(evidence.covers('Vault.sol',Number(huge.start),Number(huge.end)),false);
    assert.ok(result.nextOffset===null||result.nextOffset>offset);offset=result.nextOffset;
    assert.ok(turns<100);
  }
  assert.ok(evidence.covers('Vault.sol',Number(huge.start),Number(huge.end)));
  const all=[];offset=0;
  while(offset!==null) {const page=await index.outline(join(root,'Vault.sol'),offset,700);all.push(...page.items);offset=page.nextOffset;assert.ok(JSON.stringify(page).length<=700);}
  assert.deepEqual(all,outline.items);
  await writeFile(join(root,'Bad.sol'),'contract Broken { function');
  await assert.rejects(index.outline(join(root,'Bad.sol'),0,2000));
  await writeFile(join(root,'Oversize.sol'),' '.repeat(512001));
  await assert.rejects(index.outline(join(root,'Oversize.sol'),0,2000),/size limit/);
  await writeFile(join(root,'Missing.sol'),'import "@missing/Base.sol"; contract Missing is Base { function f() external {} }');
  const missing=await index.context(join(root,'Missing.sol'),'Missing.f',0,4000);
  assert.ok(missing.unresolved.some(x=>x.includes('Unresolved/ambiguous base')));
  assert.ok(missing.unresolved.some(x=>x.includes('import @missing')));
  // Explicitly supplied symlinks may not escape the hunt workspace.
  await symlink('/etc/passwd',join(root,'escape.sol'));
  await assert.rejects(index.outline(join(root,'escape.sol'),0,2000),/outside/);
  // A new acquired workspace/version must not reuse stale source from cache.
  await writeFile(join(root,'Changing.sol'),'contract C { function oldName() external {} }');
  assert.ok((await new SoliditySourceIndex(root).outline(join(root,'Changing.sol'),0,2000)).items.some(x=>x.name==='oldName'));
  await writeFile(join(root,'Changing.sol'),'contract C { function newName() external {} }');
  assert.ok((await new SoliditySourceIndex(root).outline(join(root,'Changing.sol'),0,2000)).items.some(x=>x.name==='newName'));
  // Cyclic imports terminate and unit aliases resolve without traversing outside scope.
  await writeFile(join(root,'Cycle.sol'),'import * as B from "./CycleBase.sol"; contract Cycle is B.CycleBase { function f() external {} }');
  await writeFile(join(root,'CycleBase.sol'),'import "./Cycle.sol"; contract CycleBase { uint value; }');
  assert.ok((await index.context(join(root,'Cycle.sol'),'Cycle.f',0,4000)).excerpts.some(x=>x.path==='CycleBase.sol'&&x.text.includes('uint value')));
  // Exercise both production model protocols. An outline alone is not a source read.
  await writeFile(join(root,'Tiny.sol'),'contract Tiny { uint value; function set(uint x) external { value=x; } }');
  for(const protocol of ['json','native']) {
    process.env.LOCAL_OLLAMA_TOOL_PROTOCOL=protocol;let calls=0,readCount=0;
    server.removeAllListeners('request');
    server.on('request',async(req,res)=>{
      let raw='';for await(const chunk of req)raw+=chunk;const request=JSON.parse(raw);calls++;
      if(calls===2)assert.equal(readCount,0,'Outline must not establish evidence');
      if(calls===3)assert.match(request.messages.at(-1).content,/No source file has been successfully read/);
      if(calls===4)assert.ok(readCount>0);
      const name=calls===1?'outline_solidity':calls===3?'read_solidity':'final';
      const args={path:'Tiny.sol',query:'Tiny.set',offset:0};
      res.end(JSON.stringify({message:protocol==='json'?{role:'assistant',content:JSON.stringify({action:name,...args,answer:'DONE'})}:
        name==='final'?{role:'assistant',content:'DONE'}:{role:'assistant',content:'',tool_calls:[{function:{name,arguments:args}}]}}));
    });
    if(!server.listening)await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
    process.env.AUTOHACK_OLLAMA_URL=`http://127.0.0.1:${(server.address() as any).port}/api/chat`;
    assert.equal(await runLocalAudit('Inspect Tiny.sol',join(root,protocol+'.log'),15000,root,'mock',undefined,
      {numCtx:8192,numPredict:128,onRead:(path,span)=>{assert.equal(path,'Tiny.sol');assert.ok(span.end>span.start);readCount++;}}),'DONE');
    assert.equal(calls,4);
  }
  for(const protocol of ['json','native']) {
    process.env.LOCAL_OLLAMA_TOOL_PROTOCOL=protocol;let calls=0,reads=0;
    server.removeAllListeners('request');
    server.on('request',async(req,res)=>{
      let raw='';for await(const chunk of req)raw+=chunk;const request=JSON.parse(raw);calls++;
      if(calls===2){assert.match(request.messages.at(-1).content,/Tool error/);assert.equal(reads,0);}
      const name=calls===1?'outline_solidity':calls===2?'read_file':'final';
      const args={path:'Bad.sol',query:'',offset:0};
      res.end(JSON.stringify({message:protocol==='json'?{role:'assistant',content:JSON.stringify({action:name,...args,answer:'DONE'})}:
        name==='final'?{role:'assistant',content:'DONE'}:{role:'assistant',content:'',tool_calls:[{function:{name,arguments:args}}]}}));
    });
    assert.equal(await runLocalAudit('Inspect malformed fixture',join(root,protocol+'-fallback.log'),15000,root,'mock',undefined,
      {numCtx:8192,numPredict:128,onRead:()=>reads++}),'DONE');
    assert.equal(reads,1);
  }
  console.log('Solidity AST outline, aliases/inheritance/modifiers, exact spans, bounded context, cache invalidation, fallback and both model protocols PASSED');
} finally {server.closeAllConnections();server.close();await rm(root,{recursive:true,force:true});}
