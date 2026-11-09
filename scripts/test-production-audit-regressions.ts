/** Shared production routing tests. Injected outcomes test scheduling only;
 * the separate hosted matrix must execute and independently replay real cases. */
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';
import {InvestigationWorkflow} from '../packages/security-solver/src/investigation-workflow';
import {controllerPolyglotPlans} from '../packages/security-solver/src/controller-polyglot-plan';
import {ControllerEvidenceArchive} from '../packages/security-solver/src/controller-evidence-archive';
const root=await mkdtemp(join(tmpdir(),'lotus-audit-regressions-'));
const keys=['AUTOHACK_OLLAMA_URL','LOCAL_CONTROLLER_FULL_SOURCE_INDEX','LOCAL_CONTROLLER_OWNED_ACTIONS','AUTOHACK_AUTO_SOURCE_PREFETCH','LOCAL_OLLAMA_TOOL_PROTOCOL','LOCAL_MODEL_ADAPTER'];
const saved=Object.fromEntries(keys.map(k=>[k,process.env[k]]));
let generations=0;
const server=createServer(async(req,res)=>{
  let body='';for await(const chunk of req)body+=chunk;
  const request=JSON.parse(body);generations++;
  assert.deepEqual(request.format.properties.action.enum,['final'], 'model can only assess; controller selects all reads and probes');
  res.end(JSON.stringify({message:{content:JSON.stringify({action:'final',path:'',query:'',answer:'{"assessed":true}'})}}));
});
try {
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  process.env.AUTOHACK_OLLAMA_URL='http://127.0.0.1:'+(server.address() as any).port+'/api/chat';
  process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX='true';process.env.LOCAL_CONTROLLER_OWNED_ACTIONS='true';
  process.env.AUTOHACK_AUTO_SOURCE_PREFETCH='false';process.env.LOCAL_OLLAMA_TOOL_PROTOCOL='json';process.env.LOCAL_MODEL_ADAPTER='ollama';
  const fixtures=[
    ['render.py','def safe(value):\n    return "<p>safe</p>"\ndef render(value):\n    return "<p>"+value+"</p>"\n','safe','render'],
    ['render.cjs','exports.safe=function(value){return "<p>safe</p>";};\nexports.render=function(value){return "<p>"+value+"</p>";};','safe','render'],
    ['Render.java','public class Render {public static String safe(String value){return "<p>safe</p>";} public static String render(String value){return "<p>"+value+"</p>";}}','Render.safe','Render.render'],
    ['Counter.sol','pragma solidity ^0.8.0; contract Counter {uint public value; function first(uint amount) public {value+=amount;} function second(uint amount) public {value+=amount;}}','Counter.first','Counter.second'],
  ];
  await mkdir(join(root,'source-1'));
  for(const [name,code,first,second] of fixtures) {
    const path='source-1/'+name;await writeFile(join(root,path),code);
    if(!name.endsWith('.sol'))assert.ok(controllerPolyglotPlans(path,code).some(p=>p.query===second),name+': enumerate beyond first declaration');
    const attempted:string[]=[];const before=generations;const log=join(root,name+'.log');
    const checkpoint=join(root,name+'.checkpoint.json');
    await writeFile(checkpoint+'.memory.json',JSON.stringify({version:1,notes:['Prior navigation; replay required'],evidenceReferences:['f'.repeat(64)]}));
    await runLocalAudit('Assess source-grounded observations.',log,20000,root,'mock',undefined,{
      productionWorkflow:true,controllerIndex:true,maxTurns:24,numCtx:8192,numPredict:256,
      checkpointPath:checkpoint,initialSourcePaths:[path],
      verifyPython:async(_path,selector)=>{
        attempted.push(selector);
        return JSON.stringify(attempted.length>=2?{status:'behavior_observed',behavior_observed:true,caseId:'a'.repeat(64)}:{status:'unsupported_execution',behavior_observed:false});
      },
      onVerifiedCase:async()=>({callers:[path]}),
      validateFinal:answer=>JSON.parse(answer).assessed?null:'Missing assessment'
    });
    assert.ok(attempted.includes(first),name);assert.ok(attempted.includes(second),name+': unsupported first candidate cannot starve a later declaration');
    assert.equal(new Set(attempted).size,attempted.length,name+': never repeat unsupported methods');
    assert.equal(generations-before,1,name+': exactly one semantic assessment');
    assert.ok(!(await readFile(log,'utf8')).includes('Missing controller evidence reference'),name);
  }
  // Negative-only observations have a final-only transition after actual source
  // exhaustion. They never gain a case, success credit, or invented impact.
  const path='source-1/negative.py';await writeFile(join(root,path),'def render(value):\n    return "<p>safe</p>"\n');
  let negatives=0;
  await runLocalAudit('Assess the negative observation.',join(root,'negative.log'),20000,root,'mock',undefined,{
    productionWorkflow:true,controllerIndex:true,maxTurns:12,numCtx:8192,numPredict:256,
    initialSourcePaths:[path],verifyPython:async()=>{negatives++;return JSON.stringify({status:'behavior_not_observed',behavior_observed:false});},
    validateFinal:answer=>JSON.parse(answer).assessed?null:'Missing assessment'
  });
  assert.equal(negatives,1);
  const restored=new InvestigationWorkflow();restored.restore({version:1,notes:['Prior navigation'],evidenceReferences:['b'.repeat(64)]});
  assert.deepEqual(restored.memory().evidenceReferences,[],'prior-run archive IDs are not current-run evidence');
  const archive=new ControllerEvidenceArchive(join(root,'cold.jsonl'));
  const id=await archive.append('source',{value:1});const parents=[id];
  const child=await archive.append('probe',{status:'observed'},{parentIds:parents});parents.length=0;
  const copy=(await archive.retrieve(child))!;copy.parentIds.length=0;(copy.payload as any).status='forged';
  assert.deepEqual((await archive.retrieve(child))?.parentIds,[id]);
  assert.deepEqual((await archive.retrieve(child))?.payload,{status:'observed'});
  console.log('Four-language candidate progression, negative assessment, restart memory and immutable archive regressions PASSED');
} finally {
  server.closeAllConnections();server.close();
  for(const [k,v] of Object.entries(saved)){if(v===undefined)delete process.env[k];else process.env[k]=v;}
  await rm(root,{recursive:true,force:true});
}
