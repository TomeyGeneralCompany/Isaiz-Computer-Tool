import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {generate} from './lotus-gauntlet-fixtures';
import {guidedProbeAcrossSourceChain} from '../packages/security-solver/src/source-guided-probes';
import {SoliditySourceIndex} from '../packages/security-solver/src/solidity-source-index';
import {buildBaselineSequence} from '../packages/security-solver/src/solidity-probe-inputs';
import {inspectGauntletEvents} from './gauntlet-probe-telemetry';
import {callerLineReferences} from '../packages/security-solver/src/source-function-reference';

const pyWithImport='from src.pipeline import wrap_fragment\ndef render(value):\n    return wrap_fragment(value)';
assert.equal(callerLineReferences(pyWithImport,1,'wrap_fragment'),false);
assert.equal(callerLineReferences(pyWithImport,3,'wrap_fragment'),true);
const repo=await mkdtemp(join(tmpdir(),'lotus-polyglot-replay-'));
try {
  for(const language of ['javascript','python','java'] as const) {
    const fixture=generate(language,12);
    for(const [path,source] of Object.entries(fixture.files)) {
      if(path.includes('modules/'))continue;
      const full=join(repo,'source-1',path);
      await mkdir(dirname(full),{recursive:true});
      await writeFile(full,source);
    }
    const path='source-1/'+fixture.answer.file;
    const hint=await guidedProbeAcrossSourceChain(repo,path,fixture.files[fixture.answer.file]);
    assert.equal(hint?.functionName,fixture.answer.selector,
      language+' controller must trace the fixture real caller -> helper chain');
    assert.equal(hint?.kind,'html_reflection');
  }

  const fixture=generate('solidity',12);
  const sourcePath=join(repo,'SettlementAuthority.sol');
  await writeFile(sourcePath,fixture.files['contracts/settlement/SettlementAuthority.sol']);
  const index=new SoliditySourceIndex(repo);
  const menu=await index.probeMenu(sourcePath,30);
  assert.ok(menu.some(item=>item.selector==='SettlementAuthority.operator'&&item.operation==='call'),
    'ABI-generated public state getter must be offered as a read');
  const plan=buildBaselineSequence(menu,'SettlementAuthority.rotateOperator');
  assert.ok(plan,'controller must construct an executable ABI-backed state transition');
  assert.equal(plan!.steps[0].operation,'observe');
  assert.equal(plan!.steps[0].function,'operator()');
  assert.equal(plan!.steps[1].operation,'send');
  assert.equal(plan!.steps[1].function,'rotateOperator(address)');
  assert.equal(plan!.steps[1].sender,1,'challenge must test from non-deployer account');
  assert.equal(plan!.steps[2].function,'operator()');

  const digest='a'.repeat(64);
  const log=[
    '[SOURCE_MAP] 144 files',
    '[INITIAL_SOURCE_READ] '+JSON.stringify({path:'source-1/src/renderer.cjs',start:0,end:100,nextOffset:null}),
    '[GUIDED_SOURCE_PROBE] '+JSON.stringify({path:'source-1/src/renderer.cjs',
      function:'render',kind:'html_reflection',status:'behavior_observed',caseId:digest}),
  ].join('\n');
  const grounded=inspectGauntletEvents(log,{
    file:'src/renderer.cjs',selector:'render'
  },true);
  assert.ok(grounded.sourceRead && grounded.targetRead && grounded.targetProbe &&
    grounded.executedAny && grounded.plannedAny && grounded.verifiedFinding);
  assert.equal(grounded.completedCount,1);
  const promotedLog=[
    '[INITIAL_SOURCE_READ] '+JSON.stringify({path:'source-1/src/pipeline.cjs',
      start:0,end:140,nextOffset:null}),
    '[CONTROLLER_CALLER_PROBE] '+JSON.stringify({
      path:'source-1/src/renderer.cjs',function:'render',kind:'html_reflection',
      status:'behavior_observed',caseId:digest}),
    '[READ_OK] source-1/src/renderer.cjs offset=0 end=142 nextOffset=null'
  ].join('\n');
  const promoted=inspectGauntletEvents(promotedLog,{file:'src/renderer.cjs',selector:'render'},true);
  assert.ok(promoted.targetRead&&promoted.targetProbe&&promoted.executedAny);
  assert.equal(promoted.counters.controllerCallerProbes,1);
  const fake=inspectGauntletEvents([
    '[MODEL_ACTION] '+JSON.stringify({action:'read_file',path:'source-1/src/renderer.cjs'}),
    '[GUIDED_SOURCE_PROBE] '+JSON.stringify({path:'source-1/src/adapter.cjs',
      function:'render',status:'invalid_probe'})
  ].join('\n'),{file:'src/renderer.cjs',selector:'render'},false);
  assert.equal(fake.targetRead,false,'model requests do not prove the source was read');
  assert.equal(fake.targetProbe,false,'invalid/irrelevant probes do not count as target evidence');
  assert.equal(fake.verifiedFinding,false);
  console.log('LOTUS polyglot source chain, Solidity public getter, and controller-owned grading PASSED');
}finally{
 await rm(repo,{recursive:true,force:true});
}
