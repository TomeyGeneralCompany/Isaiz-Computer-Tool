import 'dotenv/config';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,cp,rm} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {dirname,join} from 'node:path';
import {tmpdir} from 'node:os';
import {generateCrucible} from './lotus-crucible-generator';
import {createCrucibleInvestigatorPackage} from './lotus-crucible-contract';
import {runLocalProgramHunt,independentReview} from '../packages/security-solver/src/local-program-flow';

const root=await mkdtemp(join(tmpdir(),'lotus-consumer-independent-review-'));
const old={project:process.env.PROJECT_ROOT,token:process.env.GITHUB_TOKEN,
 index:process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX,owned:process.env.LOCAL_CONTROLLER_OWNED_ACTIONS};
const url='https://github.com/fixture/owned';
try{
 process.env.PROJECT_ROOT=join(root,'work');
 process.env.GITHUB_TOKEN='owned-fixture';
 process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX='true';
 process.env.LOCAL_CONTROLLER_OWNED_ACTIONS='true';
 await mkdir(process.env.PROJECT_ROOT);
 const challenge=generateCrucible({language:'solidity',seed:'independent-role-consumer-review-20261106'});
 const files=createCrucibleInvestigatorPackage(challenge).files;
 const fixture=join(root,'fixture');
 for(const [path,source] of Object.entries(files)){
  const full=join(fixture,path);await mkdir(dirname(full),{recursive:true});await writeFile(full,source);
 }
 execFileSync('git',['init','-q',fixture]);
 execFileSync('git',['-C',fixture,'add','.']);
 execFileSync('git',['-C',fixture,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
  'commit','-qm','Owned Solidity independent-review regression']);
 const acquirer=async(requested:string,destination:string)=>{
  assert.equal(requested,url);
  await cp(fixture,destination,{recursive:true,errorOnExist:true,force:false});
  return {missingDependencies:[]};
 };
 const program:any={id:'solidity-consumer-independent-review',provider:'immunefi',
  name:'Owned protected consumer',scopeSummary:JSON.stringify({
   policy:'Owned source only. Local technical review permitted. No external submissions.',
   scopes:[{assetType:'SOURCE_CODE',eligibleForBounty:true,assetIdentifier:url}]
  })};
 const result=await runLocalProgramHunt(program,undefined,undefined,undefined,false,acquirer);
 assert.equal(result.success,true,JSON.stringify({error:result.error,coverage:result.coverage}));
 const expected=challenge.privateAnswerKey.defects.map(d=>d.affectedPaths.at(-1)!).sort();
 const actual=result.findings.map(f=>String(f.targetAsset).split(url+'/')[1]).sort();
 assert.deepEqual(actual,expected,'All five source-linked role escalations must have independently measured consumer consequences');
 for(const [i,finding] of result.findings.entries()){
  assert.match(finding.reproductionCaseId||'',/^[a-f0-9]{64}$/);
  const review=await independentReview({...finding,id:'solidity-consumer-review-'+i} as any,
   program,finding.reproductionCaseId!,new AbortController().signal,acquirer);
  assert.equal(review.review.verdict,'approve','Independent EVM replay must validate the actual protected consumer '+i);
  assert.equal(review.review.recommendation,'dont_submit','No real bounty submission is permitted');
 }
 console.log('Solidity 2000-file full hunt, five protected-consumer cases independently replayed and reviewed PASSED');
}finally{
 for(const [name,value] of Object.entries({
  PROJECT_ROOT:old.project,GITHUB_TOKEN:old.token,
  LOCAL_CONTROLLER_FULL_SOURCE_INDEX:old.index,LOCAL_CONTROLLER_OWNED_ACTIONS:old.owned
 })){if(value===undefined)delete process.env[name];else process.env[name]=value;}
 await rm(root,{recursive:true,force:true});
}
