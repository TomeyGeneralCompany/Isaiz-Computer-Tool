/** Real controller entry replay: the controller discovers the route from
 * 2,000 source files, then the existing sandbox independently executes the
 * attacker-input boundary and the terminal sink. No Qwen file navigation.
 */
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {execFileSync} from 'node:child_process';
import {generateCrucible} from './lotus-crucible-generator';
import {indexedEntryRoutes} from '../packages/security-solver/src/controller-indexed-route';
import {createProbeSession,replaySourceCase} from '../packages/security-solver/src/source-reproduction';

for(const language of ['python','java'] as const){
 const workspace=await mkdtemp(join(tmpdir(),'lotus-indexed-entry-replay-'));
 const repo=join(workspace,'source-1'),url='https://github.com/fixture/owned';
 try{
  const challenge=generateCrucible({language,seed:'entry-runtime-check-20261106'});
  const eligible:string[]=[];
  for(const [path,body] of Object.entries(challenge.files)){
   const full=join(repo,path);
   await mkdir(dirname(full),{recursive:true});await writeFile(full,body);
   if(/\.(?:py|java)$/.test(path))eligible.push('source-1/'+path);
  }
  execFileSync('git',['init','-q',repo]);
  execFileSync('git',['-C',repo,'add','.']);
  execFileSync('git',['-C',repo,'-c','user.name=Fixture','-c','user.email=fixture@example.test',
    'commit','-qm','Owned generated entry-runtime regression']);
  const routes=await indexedEntryRoutes(workspace,eligible);
  const key=challenge.privateAnswerKey.defects[0];
  const entry='source-1/'+key.entryPath;
  const route=routes.find(r=>r.entry===entry);
  assert.ok(route,language+': controller must find a source-backed entry');
  assert.equal(route.chain.length,key.affectedPaths.length);
  assert.deepEqual(route.chain,key.affectedPaths.map(p=>'source-1/'+p));
  const program:any={id:'owned-route-'+language,provider:'immunefi',
   name:'Owned controller source entry runtime',scopeSummary:JSON.stringify({
    policy:'Only generated local source may be tested.',
    scopes:[{assetType:'SOURCE_CODE',eligibleForBounty:true,assetIdentifier:url}]})};
  const session=await createProbeSession(program,workspace,[{directory:repo,url}]);
  const entryResult=JSON.parse(await session.probe(entry,route.selector,'entry_html_reflection'));
  assert.equal(entryResult.status,'behavior_observed',
    language+': sandbox must independently observe actual unescaped entry output; '+JSON.stringify(entryResult));
  assert.match(entryResult.caseId,/^[a-f0-9]{64}$/);
  assert.equal((await replaySourceCase(session.cases.get(entryResult.caseId)!,repo)).behavior_observed,true);
  const selector=language==='java'
   ? route.sink.split('/').at(-1)!.replace(/\.java$/,'')+'.project':'project';
  const sink=JSON.parse(await session.probe(route.sink,selector,'html_reflection'));
  assert.equal(sink.status,'behavior_observed',
    language+': terminal must be independently reproduced');
  assert.match(sink.caseId,/^[a-f0-9]{64}$/);
  assert.equal((await replaySourceCase(session.cases.get(sink.caseId)!,repo)).behavior_observed,true);
  assert.equal(session.completedProbes,2);
  console.log(language+': full 2000-file source graph to independently replayed entry and sink PASSED');
 }finally{await rm(workspace,{recursive:true,force:true});}
}
