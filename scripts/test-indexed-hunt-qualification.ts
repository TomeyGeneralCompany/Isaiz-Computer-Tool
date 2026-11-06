import 'dotenv/config';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,cp,rm} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {dirname,join} from 'node:path';
import {tmpdir} from 'node:os';
import {generateCrucible} from './lotus-crucible-generator';
import {createCrucibleInvestigatorPackage} from './lotus-crucible-contract';
import {runLocalProgramHunt} from '../packages/security-solver/src/local-program-flow';

const root=await mkdtemp(join(tmpdir(),'lotus-indexed-hunt-qualification-'));
const old={project:process.env.PROJECT_ROOT,token:process.env.GITHUB_TOKEN,
 index:process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX,owned:process.env.LOCAL_CONTROLLER_OWNED_ACTIONS};
const url='https://github.com/fixture/owned';
try{
 process.env.PROJECT_ROOT=join(root,'work');
 process.env.GITHUB_TOKEN='owned-fixture';
 process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX='true';
 process.env.LOCAL_CONTROLLER_OWNED_ACTIONS='true';
 await mkdir(process.env.PROJECT_ROOT);
 for(const language of ['python','solidity'] as const){
   const challenge=generateCrucible({language,seed:'qualification-indexed-evidence-20261106'});
   const files=createCrucibleInvestigatorPackage(challenge).files;
   const fixture=join(root,'fixture-'+language);
   for(const [path,source] of Object.entries(files)){
     const full=join(fixture,path);await mkdir(dirname(full),{recursive:true});
     await writeFile(full,source);
   }
   execFileSync('git',['init','-q',fixture]);
   execFileSync('git',['-C',fixture,'add','.']);
   execFileSync('git',['-C',fixture,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','Indexed production regression']);
   const acquirer=async (requested:string,destination:string)=>{
     assert.equal(requested,url);
     await cp(fixture,destination,{recursive:true,errorOnExist:true,force:false});
     return {missingDependencies:[]};
   };
   const program:any={id:'indexed-qualification-'+language,provider:'immunefi',
     name:'Owned 2000 source qualification',scopeSummary:JSON.stringify({
       policy:'Owned source only. Local reproduction and independent technical review authorized; no external submissions.',
       scopes:[{assetType:'SOURCE_CODE',eligibleForBounty:true,assetIdentifier:url}]
     })};
   const result=await runLocalProgramHunt(program,undefined,undefined,undefined,false,acquirer);
   assert.equal(result.success,true,language+' '+JSON.stringify({error:result.error,coverage:result.coverage}));
   const targets=result.findings.map(f=>String(f.targetAsset).split(url+'/')[1]).sort();
   const expected=challenge.privateAnswerKey.defects.map(x=>x.affectedPaths.at(-1)!).sort();
   assert.deepEqual(targets,expected,language+' must report exactly the five reproduced sinks');
   assert.ok(result.findings.every(f=>/^[a-f0-9]{64}$/.test(f.reproductionCaseId||'')));
   console.log(language+': 2000-file actual runLocalProgramHunt, five verified cases and reports PASSED');
 }
}finally{
 for(const [name,value] of Object.entries({
  PROJECT_ROOT:old.project,GITHUB_TOKEN:old.token,
  LOCAL_CONTROLLER_FULL_SOURCE_INDEX:old.index,LOCAL_CONTROLLER_OWNED_ACTIONS:old.owned
 })){if(value===undefined)delete process.env[name];else process.env[name]=value;}
 await rm(root,{recursive:true,force:true});
}
