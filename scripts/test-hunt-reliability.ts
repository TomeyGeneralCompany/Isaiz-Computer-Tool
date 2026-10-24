import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm,symlink,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {compilerCompatible,inspectSourceCapability} from '../packages/security-solver/src/source-capability';
import {referencesProbedFunction,callerLineReferences,transactionEntryLine} from '../packages/security-solver/src/source-function-reference';
import {compactAuditContext,auditCheckpoint} from '../packages/security-solver/src/audit-context';
import {programCandidateBlocker,LOCAL_REPRODUCTION_CAPABILITY_VERSION} from '../packages/core/src/program-eligibility';
import {loadConfig} from '../packages/core/src/config';
for(const range of ['^0.8.20','>=0.8.0 <0.9.0','0.8.30','^0.7.0 || ^0.8.0'])assert.equal(compilerCompatible(range),true,range);
for(const range of ['^0.7.0','0.8.19','>=0.8.31','~0.7.1'])assert.equal(compilerCompatible(range),false,range);
assert.equal(compilerCompatible('0.8.x'),null);
assert.equal(compilerCompatible('0.7.0 - 0.9.0'),null);
for(const line of ['// target.set(x);','function set(uint x) external {}','const text = "target.set(x)";','/* target.set(x); */'])assert.equal(referencesProbedFunction(line,'Store.set'),false,line);
assert.equal(referencesProbedFunction('target.set(x);','Store.set'),true);
assert.equal(callerLineReferences('/*\ntarget.set(x);\n*/',2,'Store.set'),false);
assert.equal(transactionEntryLine('function set(uint x) external {}',1,'Store.set'),true);
assert.equal(transactionEntryLine('// function set(uint x) external {}',1,'Store.set'),false);
const pinned=[{role:'system',content:'instructions'},{role:'user',content:'task'}];
const messages=[...pinned];
for(let i=0;i<80;i++)messages.push({role:'assistant',content:'call '+i},{role:'tool',content:'x'.repeat(1000)});
const compact=compactAuditContext(messages,4000);
assert.deepEqual(compact.slice(0,2),pinned);assert.ok(JSON.stringify(compact).length<=4000);
assert.equal(compact[2].role,'assistant');assert.equal(compact.at(-2)!.content,'call 79');
assert.doesNotThrow(()=>JSON.parse(auditCheckpoint(Array(80).fill('read Store.sol offset 2000'))));
const root=await mkdtemp(join(tmpdir(),'capability-'));
try {
 execFileSync('git',['init','-q',root]);
 await writeFile(join(root,'Old.sol'),'pragma solidity ^0.7.0; contract Old {}');
 execFileSync('git',['-C',root,'add','.']);
 assert.equal((await inspectSourceCapability(root)).blocked,true);
 await writeFile(join(root,'New.sol'),'pragma solidity ^0.8.0; contract New {}');
 execFileSync('git',['-C',root,'add','.']);
 const mixed=await inspectSourceCapability(root);
 assert.equal(mixed.blocked,false,'One incompatible file must not block a mixed project');
 assert.deepEqual(mixed.sourcePaths,['New.sol'],'Preflight exposes compatible source paths, excluding unsupported compiler files');
 await writeFile(join(root,'Render.java'),'public class Render {}');
 execFileSync('git',['-C',root,'add','.']);
 assert.ok((await inspectSourceCapability(root)).sourcePaths.includes('Render.java'));
 await symlink('absent.sol',join(root,'Broken.sol'));
 execFileSync('git',['-C',root,'add','.']);
 const withLink=await inspectSourceCapability(root);
 assert.equal(withLink.blocked,false);assert.ok(withLink.unsupported.some(x=>x.includes('symlink')));
 // Only the nested gitlink contains runnable code; recurse through two levels.
 const parent=join(root,'parent'), child=join(parent,'child'), nested=join(child,'nested');
 await mkdir(nested,{recursive:true});
 for(const dir of [parent,child,nested])execFileSync('git',['init','-q',dir]);
 await writeFile(join(nested,'Owned.sol'),'pragma solidity ^0.8.20; contract Owned {}');
 for(const [dir,name] of [[parent,'child'],[child,'nested']]) {
   await writeFile(join(dir,'.gitmodules'),`[submodule "${name}"]\n path = ${name}\n url = https://github.com/fixture/${name}\n`);
   execFileSync('git',['-C',dir,'config',`submodule.${name}.url`,`https://github.com/fixture/${name}`]);
 }
 for(const dir of [nested,child]) {
   execFileSync('git',['-C',dir,'add','.'],{stdio:'pipe'});
   execFileSync('git',['-C',dir,'-c','user.name=Fixture','-c','user.email=fixture@example.test','commit','-qm','fixture']);
 }
 execFileSync('git',['-C',parent,'add','.'],{stdio:'pipe'});
 const nestedCapability=await inspectSourceCapability(parent);
 assert.equal(nestedCapability.blocked,false,'Nested submodule sources must be inspected');
 assert.equal(nestedCapability.compatibleFiles,1);
 await writeFile(join(nested,'Owned.sol'),'pragma solidity ^0.7.0; contract Owned {}');
 assert.equal((await inspectSourceCapability(parent)).blocked,true,'Unsupported nested source still blocks');
 process.env.GITHUB_TOKEN='fixture';
 const config={...loadConfig(),IMMUNEFI_ENABLED:true,SECURITY_MIN_REWARD_CENTS:0};
 const scopes=[{assetType:'SOURCE_CODE',eligibleForBounty:true,assetIdentifier:'https://github.com/fixture/owned'}];
 const block={version:LOCAL_REPRODUCTION_CAPABILITY_VERSION,scopes:JSON.stringify(scopes),reason:'compiler',refreshAfter:new Date(Date.now()+86400000).toISOString()};
 const program:any={status:'active',provider:'immunefi',scopeSummary:JSON.stringify({scopes,capabilityBlock:block})};
 assert.equal(programCandidateBlocker(program,config,true),'unsupported_source_capability');
 for(const changed of [{...block,version:0},{...block,refreshAfter:new Date(0).toISOString()},{...block,scopes:'[]'}]) {
   program.scopeSummary=JSON.stringify({scopes,capabilityBlock:changed});
   assert.equal(programCandidateBlocker(program,config,true),null);
 }
 console.log('Caller evidence, direct transactions, compiler preflight, capability refresh and bounded history PASSED');
} finally {await rm(root,{recursive:true,force:true});}
