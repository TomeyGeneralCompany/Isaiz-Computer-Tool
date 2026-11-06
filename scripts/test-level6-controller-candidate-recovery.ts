import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {generateCrucible} from './lotus-crucible-generator';
import {rankTracedSourceCandidates} from '../packages/security-solver/src/controller-source-candidates';
import {collectStaticLeads} from '../packages/security-solver/src/local-static-leads';
import type {Language} from './lotus-gauntlet-fixtures';

const root=await mkdtemp(join(tmpdir(),'lotus-level6-candidate-repair-'));
const oldCwd=process.cwd(),oldProject=process.env.PROJECT_ROOT;
try {
  // The target's working directory must never become the installation root
  // for the packaged static scanner's configuration files.
  delete process.env.PROJECT_ROOT;
  process.chdir(root);
  const staticLeads=await collectStaticLeads(root,[],[],join(root,'static-cache.json'),
    new AbortController().signal);
  assert.equal(staticLeads.status,'navigation_only',
    'Static analyzer assets must be resolved from LOTUS, not target process.cwd()');
  process.chdir(oldCwd);
  for(const language of ['python','javascript','java'] as Language[]){
    const challenge=generateCrucible({language,seed:'controller-level6-ranking-regression-20261106'});
    const paths:string[]=[];
    const examples=[
      challenge.privateAnswerKey.defects[0].affectedPaths.at(-1)!,
      challenge.privateAnswerKey.negativeControls[0].affectedPaths[0],
      challenge.privateAnswerKey.falseLeads[0].affectedPaths[0],
    ];
    for(const path of examples){
      const full=join(root,'source-1',path);
      await mkdir(dirname(full),{recursive:true});
      await writeFile(full,challenge.files[path]);
      paths.push('source-1/'+path);
    }
    const ranked=await rankTracedSourceCandidates(root,paths,96);
    assert.ok(ranked.some(x=>x.path==='source-1/'+examples[0]),
      language+' must retain source-traced vulnerable candidates');
    assert.ok(!ranked.some(x=>x.path==='source-1/'+examples[1]),
      language+' must reject sanitized controls');
    assert.ok(!ranked.some(x=>x.path==='source-1/'+examples[2]),
      language+' must not nominate false leads');
  }
  console.log('Level 6 scanner location and source-traced polyglot candidate regressions PASSED');
} finally {
  process.chdir(oldCwd);
  if(oldProject===undefined)delete process.env.PROJECT_ROOT;
  else process.env.PROJECT_ROOT=oldProject;
  await rm(root,{recursive:true,force:true});
}
