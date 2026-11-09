/** Exercise the actual session boundary, not only controller plan generation. */
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {sourceProbeSpecSchema,createProbeSession,replaySourceCase} from '../packages/security-solver/src/source-reproduction';
import {sourceStatefulPlans} from '../packages/security-solver/src/controller-stateful-candidates';

const sequence={constructor:[],steps:[{method:'advance',args:[]},{method:'advance',args:[]}]};
const nonce='a'.repeat(32);
for(const [file,kind,fn,steps] of [
  ['counter.py','python_sequence','advance',sequence],
  ['counter.js','javascript_sequence','advance',sequence],
  ['counter.cjs','javascript_sequence','advance',sequence],
  ['counter.mjs','javascript_sequence','advance',sequence],
  ['Counter.java','java_sequence','Counter.advance',sequence],
  ['Counter.sol','solidity_sequence','Counter.advance',{
    constructorArgs:[],steps:[{operation:'send',function:'advance()',args:[]},
      {operation:'observe',function:'value()',args:[]}]}]
] as const) {
  assert.ok(sourceProbeSpecSchema.safeParse({file,kind,function:fn,sequence:steps,nonce}).success,file);
  assert.equal(sourceProbeSpecSchema.safeParse({file:file+'.txt',kind,function:fn,sequence:steps,nonce}).success,false,
    'sequence must never cross a source-language boundary');
  assert.equal(sourceProbeSpecSchema.safeParse({file,kind,function:'invented',sequence:steps,nonce}).success,false,
    'the selected declaration must be exercised by the sequence');
}
const root=await mkdtemp(join(tmpdir(),'lotus-session-boundary-'));
const oldRoot=process.env.PROJECT_ROOT;
const url='https://github.com/fixture/owned';
const repo=join(root,'source-1');
try {
  process.env.PROJECT_ROOT=root;
  await mkdir(repo);
  // An unsupported Java signature returns before JDK/sandbox setup. It must
  // remain an unsupported attempt, without poisoning this session's health.
  await writeFile(join(repo,'Unsupported.java'),'public class Unsupported { public long count(){ return 1; } }');
  const sources={
    'counter.py':'class Counter:\n    def __init__(self,start=0): self.value=start\n    def advance(self,by=1):\n        self.value+=by\n        return self.value\ndef make(start=0):\n    return Counter(start)\n',
    'counter.cjs':'exports.make = function(start) {let value=start; return {\n advance(by) {value += by; return value;}\n};};\n'
  };
  for(const [file,code] of Object.entries(sources))await writeFile(join(repo,file),code);
  execFileSync('git',['init','-q',repo]);
  execFileSync('git',['-C',repo,'add','.']);
  execFileSync('git',['-C',repo,'-c','user.name=Fixture','-c','user.email=fixture@example.test','commit','-qm','Owned session fixtures']);
  const program:any={id:'session-boundary',provider:'immunefi',name:'Owned fixture',scopeSummary:JSON.stringify({
    policy:'Local owned fixture only.',scopes:[{assetType:'SOURCE_CODE',eligibleForBounty:true,assetIdentifier:url}]
  })};
  const session=await createProbeSession(program,root,[{directory:repo,url}]);
  const unsupported=JSON.parse(await session.probe('source-1/Unsupported.java','Unsupported.count','html_reflection'));
  assert.equal(unsupported.status,'unsupported_execution');
  assert.equal(session.unsupportedProbes,1);
  assert.equal(session.blockedReason,null);
  assert.equal(session.failedProbes,0);
  assert.equal(session.completedProbes,0);
  assert.equal(session.cases.size,0,'an unsupported attempt is never proof');
  // This section requires the real isolated executor on GitHub-hosted CI.
  if(process.argv.includes('--isolated')) {
    for(const [file,code] of Object.entries(sources)) {
      const plan=sourceStatefulPlans(file,code)[0];
      assert.ok(plan,file);
      const out=JSON.parse(await session.probe('source-1/'+file,plan.selector,plan.kind,plan.sequence));
      assert.equal(out.status,'observation_only',JSON.stringify(out));
      assert.equal(out.behavior_observed,false);
      assert.deepEqual(out.observations.steps.map((s:any)=>s.actual),[1,2]);
      const record=session.cases.get(out.caseId);
      assert.ok(record,'session must persist the actual same-instance sequence');
      assert.equal((await replaySourceCase(record,repo)).status,'observation_only');
    }
    assert.equal(session.completedProbes,2);
    assert.equal(session.blockedReason,null,'unsupported attempt must not taint later supported execution');
  }
  console.log('Four-language spec validation, unsupported session recovery and stateful execution boundary PASSED');
} finally {
  if(oldRoot===undefined)delete process.env.PROJECT_ROOT;else process.env.PROJECT_ROOT=oldRoot;
  await rm(root,{recursive:true,force:true});
}
