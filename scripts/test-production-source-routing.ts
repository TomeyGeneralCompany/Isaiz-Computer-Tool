/** Backend configuration cannot bypass source acquisition, reproduction or review. */
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,chmod,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {usesDeterministicSourceController,runProgramHunt,runFindingSolver} from '../packages/security-solver/src/claude-runner';
const saved={model:process.env.LOCAL_OLLAMA_MODEL,root:process.env.PROJECT_ROOT,path:process.env.PATH,token:process.env.GITHUB_TOKEN};
const root=await mkdtemp(join(tmpdir(),'lotus-routing-'));
try {
 delete process.env.LOCAL_OLLAMA_MODEL;process.env.PROJECT_ROOT=root;process.env.GITHUB_TOKEN='offline-source-routing';
 for(const lang of ['python','javascript','java','solidity']) {
  const program:any={id:'owned-'+lang,name:'Owned source '+lang,provider:'fixture',scopeSummary:JSON.stringify({
    scopes:[{assetType:'SOURCE_CODE',assetIdentifier:'https://github.com/fixture/'+lang,eligibleForBounty:true}]
  })};
  assert.equal(usesDeterministicSourceController(program),true,lang);
  assert.equal(usesDeterministicSourceController({...program,scopeSummary:JSON.stringify(JSON.parse(program.scopeSummary).scopes)}),true);
  const rewriting=await runFindingSolver({id:'owned'} as any,program);
  assert.equal(rewriting.success,false);assert.deepEqual(rewriting.findings,[]);
  assert.match(rewriting.error||'',/controller-owned reproduction/);
 }
 assert.equal(usesDeterministicSourceController({scopeSummary:'{}'}),false);
 assert.equal(usesDeterministicSourceController({scopeSummary:'invalid'}),false);
 await mkdir(join(root,'bin'));const git=join(root,'bin','git');
 await writeFile(git,'#!/bin/sh\nexit 42\n');await chmod(git,0o700);process.env.PATH=join(root,'bin')+':'+saved.path;
 const source:any={id:'source-without-model-env',provider:'fixture',name:'Owned source without environment override',scopeSummary:JSON.stringify({
  scopes:[{assetType:'SOURCE_CODE',assetIdentifier:'https://github.com/fixture/owned',eligibleForBounty:true}]
 })};
 const hunt=await runProgramHunt(source);
 assert.equal(hunt.success,false);assert.match(hunt.error||'',/No authorized source repository/);
 assert.deepEqual(hunt.findings,[],'source acquisition failure must not fall back to a free-form agent');
 console.log('All source languages retain deterministic acquisition/reproduction/review authority without LOCAL_OLLAMA_MODEL PASSED');
} finally {
 for(const [k,v] of Object.entries({LOCAL_OLLAMA_MODEL:saved.model,PROJECT_ROOT:saved.root,PATH:saved.path,GITHUB_TOKEN:saved.token})){if(v===undefined)delete process.env[k];else process.env[k]=v;}
 await rm(root,{recursive:true,force:true});
}
