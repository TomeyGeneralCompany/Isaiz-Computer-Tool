import assert from 'node:assert/strict';
import {InvestigationWorkflow} from '../packages/security-solver/src/investigation-workflow';
import {decodeAuditAction} from '../packages/security-solver/src/local-audit-protocol';
import {modelProfile} from '../packages/security-solver/src/model-profile';
import {buildSourceMap} from '../packages/security-solver/src/source-map';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
const flow=new InvestigationWorkflow();
const action={action:'read_file',path:'large.py',query:'',answer:'',offset:0};
for(let i=0;i<8;i++){flow.read(action.path);flow.observe({...action,offset:i*156},JSON.stringify({start:i*156,end:(i+1)*156,nextOffset:(i+1)*156}));}
assert.deepEqual((await flow.constraints()).action,['plan_probe','continue_inspection','final']);
const continuation={...action,action:'continue_inspection',offset:1248,hypothesis:'Need the return expression to determine whether input is escaped.'};
assert.equal(flow.validate(continuation),null);flow.continueInspection(continuation);
assert.ok((await flow.constraints()).action.includes('read_file'));
assert.equal(flow.snapshot().decisions[0].offset,1248);
const restored=new InvestigationWorkflow();restored.restore(flow.memory());
assert.ok(restored.note().includes('return expression'));
assert.equal(restored.snapshot().readPaths.length,0);
assert.match(restored.validate({...action,action:'plan_probe',query:'f',answer:'html_reflection',hypothesis:'Escaping disproves reflection'})!,/Read/);
flow.continueInspection(continuation);assert.match(flow.validate(continuation)!,/already attempted/);
assert.match(flow.validate({...continuation,offset:1500,hypothesis:'A different question still has no new source evidence since the last decision.'})!,/No new source range/);
// Rejection preserves known evidence and still permits deliberate missing-context
// recovery or a corrected final, without resetting into unconditional inspection.
const rejected=new InvestigationWorkflow();
rejected.read('large.py');
rejected.observe(action,JSON.stringify({start:0,end:401,nextOffset:401}));
rejected.finalRejected('Read the next page before drawing a conclusion.');
assert.deepEqual((await rejected.constraints()).action,['plan_probe','continue_inspection','final']);
assert.equal(rejected.snapshot().pageTurns,1);
assert.equal(rejected.snapshot().sourceProgress,1);
assert.deepEqual(rejected.snapshot().readPaths,['large.py']);
const missingContext={...continuation,offset:401};
assert.equal(rejected.validate(missingContext),null);
rejected.continueInspection(missingContext);
assert.ok((await rejected.constraints()).action.includes('read_file'));
rejected.finalRejected('The required evidence is still missing.');
assert.match(rejected.validate(missingContext)!,/already attempted/);
assert.ok((await rejected.constraints()).action.includes('final'));
assert.equal(decodeAuditAction(JSON.stringify({...action,action:'final',result:{findings:[]}})).answer,'{"findings":[]}');
assert.throws(()=>decodeAuditAction(JSON.stringify({...action,result:{findings:[]}})));
const original=process.env.LOCAL_MODEL_PROFILE;
delete process.env.LOCAL_MODEL_PROFILE;assert.equal(modelProfile().name,'qwen');
assert.equal(modelProfile().options.presence_penalty,1.5);
process.env.LOCAL_MODEL_PROFILE='qwen';assert.equal(modelProfile().options.temperature,0.7);
process.env.LOCAL_MODEL_PROFILE='qwen-planner';assert.equal(modelProfile('inspect').think,false);assert.equal(modelProfile('hypothesize').think,true);assert.equal(modelProfile('review').think,true);
if(original===undefined)delete process.env.LOCAL_MODEL_PROFILE;else process.env.LOCAL_MODEL_PROFILE=original;
const dir=await mkdtemp(join(tmpdir(),'source-map-test-'));
try {
 await writeFile(join(dir,'example.py'),'def render(value):\n    return "<p>"+value+"</p>"\ndef caller(v):\n    return render(v)\n');
 const map=await buildSourceMap(dir,['example.py','../missing.py']);
 assert.equal(map.symbols[0].name,'render');assert.equal(map.symbols[0].callers[0].line,4);
 assert.equal(map.complete,false);assert.equal(map.skippedFiles,1);
}finally{await rm(dir,{recursive:true,force:true});}
console.log('Long-file decisions, continuation, restart memory, structured finals, profiles and bounded navigation PASSED');
