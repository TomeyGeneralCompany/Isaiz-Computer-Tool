import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm,symlink,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {compilerCompatible,inspectSourceCapability} from '../packages/security-solver/src/source-capability';
import {referencesProbedFunction,callerLineReferences,qualifiedCallerLineReferences,transactionEntryLine} from '../packages/security-solver/src/source-function-reference';
import {compactAuditContext,auditCheckpoint} from '../packages/security-solver/src/audit-context';
import {reviewedTargetFinding} from './gauntlet-reviewed-finding';
import {buildControllerReportPacket,controllerReportPacketText} from '../packages/security-solver/src/controller-report-packet';
import {observedJavaSourceChain} from '../packages/security-solver/src/java-source-chain';
import {retainGroundedCandidates} from '../packages/security-solver/src/inspection-coverage';
import {programCandidateBlocker,LOCAL_REPRODUCTION_CAPABILITY_VERSION} from '../packages/core/src/program-eligibility';
import {loadConfig} from '../packages/core/src/config';
const chainDir=await mkdtemp(join(tmpdir(),'lotus-java-source-chain-'));
try {
  const sourceDir=join(chainDir,'src');
  await mkdir(sourceDir,{recursive:true});
  await writeFile(join(sourceDir,'Renderer.java'),
    'class Renderer { static String render(String x){return Pipeline.wrapFragment(x);} }');
  await writeFile(join(sourceDir,'Pipeline.java'),
    'class Pipeline { static String wrapFragment(String x){return Codec.encodeFragment(x);} }');
  await writeFile(join(sourceDir,'Codec.java'),
    'class Codec { static String encodeFragment(String x){return x;} }');
  const chain=await observedJavaSourceChain(chainDir,'src/Renderer.java');
  assert.ok(chain.includes('SOURCE src/Renderer.java') &&
    chain.includes('SOURCE src/Pipeline.java') &&
    chain.includes('SOURCE src/Codec.java'),'Reviewer must receive exact transitive Java helper source');
  assert.ok(chain.includes('return x;'),'Identity codec must be observable, not guessed');
  assert.equal(await observedJavaSourceChain(chainDir,'../secret.java'),'',
    'Reviewer evidence cannot escape the selected repository');
} finally {await rm(chainDir,{recursive:true,force:true});}
const evidencePacket=buildControllerReportPacket({
  caseId:'a'.repeat(64),repositoryUrl:'https://github.com/fixture/owned',commit:'sample',
  testedFile:'src/Renderer.java',testedFunction:'Renderer.render',
  probeKind:'html_reflection',sourceSha256:'b'.repeat(64),
  callerFile:'src/HttpHandler.java',callerLine:3,
  callerCode:'return Renderer.render(userInput);',reachability:'caller',
  observations:[{input:'<tag>',actual:'<p><tag></p>'}],
  limitation:'Isolated behavior; endpoint runtime was not exercised.'
});
const packetText=controllerReportPacketText(evidencePacket);
assert.ok(packetText.includes('Renderer.render') && packetText.includes('HttpHandler.java:3'));
assert.ok(packetText.includes('Inspected caller source:') && packetText.includes('Recorded isolated observations'));
assert.throws(()=>buildControllerReportPacket({...evidencePacket,callerCode:''}),/caller line/);
assert.throws(()=>buildControllerReportPacket({...evidencePacket,caseId:'invented'}),/SHA256/);
const gradedReports=[
  {reproductionCaseId:'codec-case',title:'Codec helper',reportBody:'src/Codec.java'},
  {reproductionCaseId:'renderer-case',title:'Renderer.render injection',reportBody:'src/Renderer.java'},
];
const answer={selector:'Renderer.render',file:'src/Renderer.java'};
assert.equal(reviewedTargetFinding(gradedReports,
  [{caseId:'codec-case',verdict:'reject'},{caseId:'renderer-case',verdict:'approve'}],answer),true,
  'second supported finding can pass despite rejection of first');
assert.equal(reviewedTargetFinding(gradedReports,
  [{caseId:'codec-case',verdict:'approve'},{caseId:'renderer-case',verdict:'reject'}],answer),false,
  'approval of unrelated first finding does not pass benchmark');
assert.equal(reviewedTargetFinding(gradedReports,
  [{caseId:'codec-case',verdict:'reject'},{caseId:'renderer-case',verdict:'reject'}],answer),false,
  'reviewer rejections cannot be converted into passes');
assert.equal(reviewedTargetFinding(gradedReports,[{caseId:'unknown',verdict:'approve'}],answer),false,
  'review approval must identify a recorded finding case');
// Compiler matrix: bundled versions are 0.8.30, 0.7.6, 0.6.12, and 0.5.17.
for(const range of ['^0.8.20','>=0.8.0 <0.9.0','0.8.30','^0.7.0 || ^0.8.0','^0.7.0','~0.7.1','^0.6.0','^0.5.0'])assert.equal(compilerCompatible(range),true,range);
for(const range of ['0.8.19','>=0.8.31','^0.4.0','^0.9.0','<0.5.0'])assert.equal(compilerCompatible(range),false,range);
assert.equal(compilerCompatible('0.8.x'),null);
assert.equal(compilerCompatible('0.7.0 - 0.9.0'),null);
for(const line of ['// target.set(x);','function set(uint x) external {}','const text = "target.set(x)";','/* target.set(x); */'])assert.equal(referencesProbedFunction(line,'Store.set'),false,line);
assert.equal(referencesProbedFunction('target.set(x);','Store.set'),true);
const validReport={caseId:'observed-renderer',callerFile:'source-1/src/HttpHandler.java',callerLine:3};
const invalidReport={caseId:'observed-handler',callerFile:'source-1/src/HttpHandler.java',callerLine:1};
assert.deepEqual(retainGroundedCandidates([invalidReport,validReport],[validReport]),[validReport],
  'a verified report survives a second unsupported proposal');
assert.deepEqual(retainGroundedCandidates([invalidReport,validReport],[]),[invalidReport,validReport],
  'zero grounded reports still enter strict rejection');
assert.deepEqual(retainGroundedCandidates([validReport],[validReport]),[validReport],
  'a single supported proposal is unchanged');
assert.deepEqual(retainGroundedCandidates([invalidReport,validReport],[invalidReport,validReport]),
  [invalidReport,validReport],'fully grounded proposals remain unchanged');

assert.equal(referencesProbedFunction('public String responseBody(String userInput){return Renderer.render(userInput);}','HttpHandler.responseBody'),false,
  'Java method declaration is not a call to itself');
assert.equal(referencesProbedFunction('public String responseBody(String userInput){return Renderer.render(userInput);}','Renderer.render'),true,
  'a real qualified call in a method body remains discoverable');
assert.equal(referencesProbedFunction('return responseBody(input);','HttpHandler.responseBody'),true,
  'a real unqualified call in a return expression remains discoverable');
assert.equal(referencesProbedFunction('String responseBody(String input) {','HttpHandler.responseBody'),false,
  'package-private Java method declaration is not a caller');
assert.equal(referencesProbedFunction('def responseBody(value):','HttpHandler.responseBody'),false,
  'Python function declaration is not a caller');

const exactCallerFixture='public class HttpHandler {\n' +
  '  public String responseBody(String input) { return Renderer.render(input); }\n' +
  '}';
const unrelatedMethod='public class Adapter {\n' +
  '  public static String render(String value) { return value; }\n' +
  '  public static String inspect(String value) { return render(value); }\n' +
  '}';
assert.equal(qualifiedCallerLineReferences(exactCallerFixture,2,'Renderer.render'),true,
  'Java qualified renderer invocation is an exact caller');
assert.equal(qualifiedCallerLineReferences(unrelatedMethod,2,'Renderer.render'),false,
  'same-named Java method declaration must not impersonate a caller');
assert.equal(qualifiedCallerLineReferences(unrelatedMethod,3,'Renderer.render'),false,
  'unrelated unqualified method invocation must not impersonate an exact caller');
assert.equal(qualifiedCallerLineReferences('render(value)',1,'render'),false,
  'bare-language function names remain subject to normal caller validation');
assert.equal(qualifiedCallerLineReferences('renderer.render(input)',1,'renderer.render'),true,
  'exact qualified invocation is language-independent');
assert.equal(qualifiedCallerLineReferences('// Renderer.render(input)',1,'Renderer.render'),false,
  'comments never count as caller evidence');

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
 await writeFile(join(root,'Old.sol'),'pragma solidity ^0.4.24; contract Old {}');
 execFileSync('git',['-C',root,'add','.']);
 assert.equal((await inspectSourceCapability(root)).blocked,true);
 await writeFile(join(root,'New.sol'),'pragma solidity ^0.8.0; contract New {}');
 execFileSync('git',['-C',root,'add','.']);
 const mixed=await inspectSourceCapability(root);
 assert.equal(mixed.blocked,false,'One incompatible file must not block a mixed project');
 assert.deepEqual(mixed.sourcePaths,['New.sol'],'Preflight exposes compatible source paths, excluding unsupported compiler files');
 await writeFile(join(root,'Render.java'),'public class Render {}');
 execFileSync('git',['-C',root,'add','.']);
 assert.ok((await inspectSourceCapability(root)).sourcePaths.includes('Render.java'),'Java source remains inspectable even without a supported probe entrypoint');
 await writeFile(join(root,'Render.java'),'public class Render { public String instance(String value) { return value; } }');
 assert.ok((await inspectSourceCapability(root)).sourcePaths.includes('Render.java'),'Public instance methods remain available for local inspection');
 await writeFile(join(root,'Render.java'),'public class Render { public static String render(final String value) { return value; } }');
 assert.ok((await inspectSourceCapability(root)).sourcePaths.includes('Render.java'),'Compatible entrypoints remain available');
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
 await writeFile(join(nested,'Owned.sol'),'pragma solidity ^0.4.24; contract Owned {}');
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

// Import/re-export continuations cannot borrow a following invocation as a caller.
for(const text of ['export { render\n};\nrender(value);', 'export { render\n(value);']) {
  assert.equal(callerLineReferences(text,1,'render'),false);
}
