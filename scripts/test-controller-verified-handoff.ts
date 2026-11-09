/** Runner integration with injected verifier results. Tests workflow routing,
 * not reproduction validity; real isolated execution has a separate CI gate. */
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';
const envKeys=['AUTOHACK_OLLAMA_URL','LOCAL_OLLAMA_TOOL_PROTOCOL','AUTOHACK_AUTO_SOURCE_PREFETCH',
  'LOCAL_CONTROLLER_OWNED_ACTIONS','LOCAL_CONTROLLER_FULL_SOURCE_INDEX','LOCAL_MODEL_ADAPTER'];
const saved=Object.fromEntries(envKeys.map(k=>[k,process.env[k]]));
const root=await mkdtemp(join(tmpdir(),'lotus-verified-handoff-'));
let generations=0;
let actions:Array<Record<string,unknown>>|null=null;
const server=createServer(async(req,res)=>{
  let body='';for await(const chunk of req)body+=chunk;
  const request=JSON.parse(body);generations++;
  if(actions) {
    const next=actions.shift();assert.ok(next,'No extra model actions expected');
    res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify(next)}}));return;
  }
  assert.deepEqual(request.format.properties.action.enum,['final'],
    'Qwen may assess the locked case, never choose another action');
  res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify({
    action:'final',path:'',query:'',answer:JSON.stringify({assessed:true})
  })}}));
});
try {
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  process.env.AUTOHACK_OLLAMA_URL='http://127.0.0.1:'+(server.address() as any).port+'/api/chat';
  process.env.LOCAL_OLLAMA_TOOL_PROTOCOL='json';
  process.env.AUTOHACK_AUTO_SOURCE_PREFETCH='false';
  process.env.LOCAL_CONTROLLER_OWNED_ACTIONS='true';
  process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX='true';
  process.env.LOCAL_MODEL_ADAPTER='ollama';
  for(const [file,source] of [
    ['render.py','def render(value):\n    return "<p>"+value+"</p>"\n'],
    ['render.cjs','exports.render=function(value){return "<p>"+value+"</p>";};'],
    ['Render.java','public class Render {public static String render(String value){return "<p>"+value+"</p>";}}'],
    ['Stateful.py','class Counter:\n    def advance(self,by=1):\n        return by\ndef make(start=0):\n    return Counter(start)\n'],
    ['Stateful.cjs','exports.make=function(start){let value=start;return {advance(by){value+=by;return value;}};};'],
    ['Stateful.java','public class Stateful {private int value=0; public int advance(){return ++value;} public int current(){return value;}}'],
    ['Counter.sol','pragma solidity ^0.8.0; contract Counter {uint public value; function add(uint amount) public {value+=amount;}}']
  ]) {
    const path='source-1/'+file;
    await mkdir(join(root,'source-1'),{recursive:true});
    await writeFile(join(root,path),source);
    const log=join(root,file+'.log');
    const before=generations;
    let probes=0;
    const id='a'.repeat(64);
    const answer=await runLocalAudit('Assess the recorded local case.',log,20000,root,'mock',undefined,{
      productionWorkflow:true,maxTurns:12,numCtx:8192,numPredict:256,numThreads:1,
      initialSourcePaths:[path],
      verifyPython:async(_path,_selector,kind,sequence)=>{
        probes++;
        if(file.startsWith('Stateful')) {
          assert.ok(kind.endsWith('_sequence'),file+': source-guided path must use existing stateful adapter');
          assert.ok(sequence,file+': source-derived sequence must reach actual verifier');
        }
        return JSON.stringify({status:'behavior_observed',behavior_observed:true,caseId:id});
      },
      onVerifiedCase:async()=>({callers:[path]}),
      validateFinal:answer=>JSON.parse(answer).assessed===true?null:'Assessment required'
    });
    assert.deepEqual(JSON.parse(answer),{assessed:true},file);
    assert.equal(probes,1,file+': a locked case must not repeat its probe');
    assert.equal(generations-before,1,file+': exactly one final assessment');
    const text=await readFile(log,'utf8');
    assert.ok(text.includes('[CONTROLLER_VERIFIED_CASE_FOCUS]'),file);
    assert.ok(!text.includes('[CONTROLLER_UNRESOLVED_ACTION]'),file);
    // Anchored parsers consume controller events as individual physical lines.
    assert.ok(text.split('\n').some(line=>line.startsWith('[CONTROLLER_OWNED_ACTION]')),file);
    for(const line of text.split('\n').filter(line=>line.startsWith('[CONTROLLER_OWNED_ACTION] ')))
      assert.doesNotThrow(()=>JSON.parse(line.slice('[CONTROLLER_OWNED_ACTION] '.length)),file);
  }
  // Source canonicalization runs on the actual model action, including Java's
  // primitive state adapter. Misspelled kinds cannot bypass controller data.
  process.env.LOCAL_CONTROLLER_OWNED_ACTIONS='false';
  process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX='false';
  for(const [file,query,kind,source] of [
    ['render.py','render','html_reflection','def render(value):\n    return "<p>"+value+"</p>"\n'],
    ['render.cjs','render','html_reflection','exports.render=function(value){return "<p>"+value+"</p>";};'],
    ['State.java','State.advance','java_sequence','public class State {private int value=0; public int advance(){return ++value;} public int current(){return value;}}'],
    ['Counter.sol','Counter.add','solidity_sequence','pragma solidity ^0.8.0; contract Counter {uint public value; function add(uint amount) public {value+=amount;}}']
  ]) {
    const path='source-1/'+file;
    await writeFile(join(root,path),source);
    const action=(action:string,answer='')=>({action,path,query,answer});
    actions=[action('read_file'),{...action('plan_probe',file.endsWith('.sol')?'solidity_function':'invented_kind'),
      hypothesis:'Observe the selected source function; an unchanged result disproves the suspected effect.'},
      action('verify_source',kind),{action:'final',path:'',query:'',answer:JSON.stringify({assessed:true})}];
    let probes=0;
    await runLocalAudit('Assess the named function.',join(root,'canonical-'+file+'.log'),20000,root,'mock',undefined,{
      productionWorkflow:true,maxTurns:12,numCtx:8192,numPredict:256,numThreads:1,
      initialSourcePaths:[path],
      verifyPython:async(_path,selector,probeKind,sequence)=>{
        probes++;assert.equal(selector,query);assert.equal(probeKind,kind);
        if(kind.endsWith('_sequence'))assert.ok(sequence,'source-owned sequence required');
        return JSON.stringify({status:'behavior_observed',behavior_observed:true,caseId:'b'.repeat(64)});
      },
      onVerifiedCase:async()=>({callers:[path]}),
      validateFinal:answer=>JSON.parse(answer).assessed===true?null:'Assessment required'
    });
    assert.equal(probes,1,file+': exact selected declaration must be canonicalized');
    assert.equal(actions.length,0,file+': no correction loop expected');
    actions=null;
  }
  console.log('Four-language production runner verified-case final handoff PASSED');
} finally {
  server.closeAllConnections();server.close();
  for(const [key,value] of Object.entries(saved)){if(value===undefined)delete process.env[key];else process.env[key]=value;}
  await rm(root,{recursive:true,force:true});
}
