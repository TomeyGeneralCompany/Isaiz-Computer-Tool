import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,chmod,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {cloneAuthorizedSource,acquisitionRetryAfter} from '../packages/security-solver/src/authorized-source';
import {AuditNavigation} from '../packages/security-solver/src/audit-navigation';
import {programCandidateBlocker} from '../packages/core/src/program-eligibility';
const root=await mkdtemp(join(tmpdir(),'preparation-recovery-'));
const oldPath=process.env.PATH;
try {
 const git=join(root,'git'),count=join(root,'count');
 await writeFile(git,`#!/usr/bin/env python3
import sys,pathlib
args=sys.argv
count=pathlib.Path(${JSON.stringify(count)})
if 'clone' in args:
 n=int(count.read_text()) if count.exists() else 0
 count.write_text(str(n+1))
 target=pathlib.Path(args[-1]);target.mkdir(parents=True,exist_ok=True)
 if n==0:
  (target/'partial').write_text('partial download')
  sys.stderr.write('fatal: Could not resolve host: github.com');sys.exit(128)
 assert not (target/'partial').exists()
 (target/'source.sol').write_text('contract Owned {}')
 (target/'.gitmodules').write_text('owned fixture')
elif 'config' in args:
 sys.stdout.write('submodule.lib.path\\nlib'+chr(0)+'submodule.lib.url\\nhttps://github.com/fixture/dependency'+chr(0))
elif 'submodule' in args:
 sys.stderr.write('fatal: repository not found');sys.exit(128)
`);
 await chmod(git,0o700);process.env.PATH=root+':'+oldPath;
 const checkout=join(root,'checkout');
 const result=await cloneAuthorizedSource('https://github.com/fixture/owned',checkout,{allowPartialDependencies:true});
 assert.equal(await readFile(count,'utf8'),'2');
 assert.equal(await readFile(join(checkout,'source.sol'),'utf8'),'contract Owned {}');
 assert.deepEqual(result.missingDependencies,['lib: repository missing or authentication required']);
 await assert.rejects(cloneAuthorizedSource('https://github.com/fixture/owned',join(root,'strict')),/Command failed/);
 assert.equal(acquisitionRetryAfter({stderr:'repository not found'},1000),null);
 assert.equal(acquisitionRetryAfter({stderr:'Could not resolve host'},1000),901000);
 const program:any={status:'active',provider:'hackerone',rewardMaxCents:100000,scopeSummary:JSON.stringify({
  scopes:[{assetType:'SOURCE_CODE',eligibleForBounty:true,assetIdentifier:'https://github.com/fixture/owned'}]})};
 const config:any={HACKERONE_ENABLED:true,EXCLUDE_SECURITY_PROGRAMS:[],SECURITY_MIN_REWARD_CENTS:0};
 const tracking=JSON.parse(program.scopeSummary);
 tracking.sourceAcquisition={scopes:JSON.stringify(tracking.scopes),checks:{'https://github.com/fixture/owned':{reason:'missing',retryAfter:null}}};
 program.scopeSummary=JSON.stringify(tracking);
 assert.equal(programCandidateBlocker(program,config,true),'source_acquisition_blocked');
 tracking.scopes.push({assetType:'SOURCE_CODE',eligibleForBounty:true,assetIdentifier:'https://github.com/fixture/new'});
 program.scopeSummary=JSON.stringify(tracking);
 assert.equal(programCandidateBlocker(program,config,true),null);
 const nav=new AuditNavigation();
 nav.observe('list_files','.',0,'',{entries:['file a.sol','file b.sol','dir nested'],nextOffset:null});
 assert.match(nav.hint(),/"path":"a.sol"/);
 nav.observe('read_file','a.sol',0,'',{end:200,nextOffset:200});
 nav.observe('read_file','b.sol',0,'',{end:100,nextOffset:null});
 nav.observe('list_files','nested',0,'',{entries:[],nextOffset:null});
 assert.match(nav.hint(),/"path":"a.sol","offset":200/);
 assert.equal(nav.snapshot().recent[1].end,200);
 console.log('Preparation retries, partial dependency acquisition, persistent blockers and concrete navigation PASSED');
} finally {process.env.PATH=oldPath;await rm(root,{recursive:true,force:true});}
