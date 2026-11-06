import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {dirname,join} from 'node:path';
import {tmpdir} from 'node:os';
import {generateCrucible} from './lotus-crucible-generator';
import {indexedEntryRoutes} from '../packages/security-solver/src/controller-indexed-route';
import {createProbeSession,replaySourceCase} from '../packages/security-solver/src/source-reproduction';

const root=await mkdtemp(join(tmpdir(),'lotus-indexed-runtime-route-'));
try{
  for(const language of ['python','javascript','java'] as const){
    const challenge=generateCrucible({language,seed:'controller-verified-routes-20261106'});
    const workspace=join(root,language);
    const repo=join(workspace,'source-1');
    const paths:string[]=[];
    for(const [path,body] of Object.entries(challenge.files)){
      const full=join(repo,path);await mkdir(dirname(full),{recursive:true});
      await writeFile(full,body);
      if(/\.(?:py|cjs|java)$/.test(path))paths.push('source-1/'+path);
    }
    execFileSync('git',['init','-q',repo]);
    execFileSync('git',['-C',repo,'add','.']);
    execFileSync('git',['-C',repo,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','Owned indexed route runtime fixture']);
    const url='https://github.com/fixture/owned';
    const program:any={id:'indexed-entry-'+language,provider:'immunefi',name:'Owned verified route',
      scopeSummary:JSON.stringify({policy:'Local, owned source verification only',scopes:[
        {assetType:'SOURCE_CODE',eligibleForBounty:true,assetIdentifier:url}]})};
    const session=await createProbeSession(program,workspace,[{directory:repo,url}]);
    const routes=await indexedEntryRoutes(workspace,paths);
    assert.ok(routes.length>=5,language+' must identify source-connected gateways');
    const observed:string[]=[];
    for(const route of routes.slice(0,24)){
      const entry=JSON.parse(await session.probe(route.entry,route.selector,'entry_html_reflection'));
      if(entry.status!=='behavior_observed')continue;
      assert.match(entry.caseId,/^[a-f0-9]{64}$/);
      const recorded=session.cases.get(entry.caseId)!;
      assert.equal((await replaySourceCase(recorded,repo)).behavior_observed,true,
        'Entry behavior must replay independently');
      const sinkSelector=language==='java'
        ?route.sink.split('/').at(-1)!.replace(/\.java$/,'')+'.project':'project';
      const terminal=JSON.parse(await session.probe(route.sink,sinkSelector,'html_reflection'));
      assert.equal(terminal.status,'behavior_observed');
      assert.match(terminal.caseId,/^[a-f0-9]{64}$/);
      observed.push(route.entry);
    }
    const expected=challenge.privateAnswerKey.defects.map(x=>'source-1/'+x.entryPath);
    assert.deepEqual(observed.slice().sort(),expected.slice().sort(),
      language+': all five independently reproduced entry routes, no safe controls');
    console.log(language+' indexed source route, entry and terminal replay: '+observed.length+' VERIFIED');
  }
}finally{await rm(root,{recursive:true,force:true});}
