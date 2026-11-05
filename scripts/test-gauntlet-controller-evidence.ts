import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {generate} from './lotus-gauntlet-fixtures';
import {rankTracedSourceCandidates} from '../packages/security-solver/src/controller-source-candidates';
import {gradeInvestigationEvents} from './lotus-gauntlet-event-grade';

for(const language of ['python','javascript','java'] as const){
  const root=await mkdtemp(join(tmpdir(),'lotus-polyglot-evidence-'));
  try {
    const challenge=generate(language,16);
    const paths:string[]=[];
    for(const [path,content] of Object.entries(challenge.files)) {
      const name='source-1/'+path, full=join(root,name);
      await mkdir(dirname(full),{recursive:true});
      await writeFile(full,content);
      paths.push(name);
    }
    // Reverse ordering demonstrates that the controller selects by evidence,
    // not by relying on the first generated fixture file.
    const ranked=await rankTracedSourceCandidates(root,paths.reverse());
    assert.ok(ranked.length,language+' should produce source-backed candidate');
    assert.equal(ranked[0].path,'source-1/'+challenge.answer.file,
      language+' must prioritize the vulnerable entry rather than a sanitized decoy/helper');
    assert.equal(ranked[0].selector,challenge.answer.selector);
    assert.ok(ranked[0].chain.length>=2,'source helper chain must be traced');
    const graderLog=[
      '[ACQUISITION_REPOSITORY_DONE] {}',
      '[SOURCE_MAP] {}',
      '[INITIAL_SOURCE_READ] '+JSON.stringify({path:'source-1/'+challenge.answer.file}),
      '[CONTROLLER_SOURCE_PROBE_SELECTED] '+JSON.stringify({path:'source-1/'+challenge.answer.file,selector:challenge.answer.selector,kind:'html_reflection'}),
      '[GUIDED_SOURCE_PROBE] '+JSON.stringify({path:'source-1/'+challenge.answer.file,function:challenge.answer.selector,status:'behavior_observed'})
    ].join('\n');
    const events=gradeInvestigationEvents(graderLog,challenge.answer);
    assert.ok(events.targetRead && events.targetPlan && events.targetAttempt && events.targetBehaviorObserved);
    assert.equal(events.counters.recordedProbeResults,1);
    assert.ok(!gradeInvestigationEvents(graderLog.replace('behavior_observed','observation_only'),challenge.answer).targetBehaviorObserved,
      'an unproven probe remains unproven despite valid execution');
    console.log(language+' source-traced candidate ranking and controller-aware Gauntlet grading PASSED');
  } finally {await rm(root,{recursive:true,force:true});}
}
