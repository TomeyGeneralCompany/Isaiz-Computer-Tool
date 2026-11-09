import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {controllerOwnedNextAction,canonicalSourceNavigationAction} from '../packages/security-solver/src/controller-next-action';
import {sourceCandidateEvidence,verifiedProbeSummary} from '../packages/security-solver/src/source-candidate-evidence';
import {traceSourceCalls} from '../packages/security-solver/src/source-flow-facts';
import {InvestigationWorkflow} from '../packages/security-solver/src/investigation-workflow';
import {guidedSourceProbe} from '../packages/security-solver/src/source-guided-probes';
import {buildSourceMap} from '../packages/security-solver/src/source-map';
import {SoliditySourceIndex} from '../packages/security-solver/src/solidity-source-index';
import {buildBaselineSequence} from '../packages/security-solver/src/solidity-probe-inputs';
import {privilegedRoleMutationCandidate} from '../packages/security-solver/src/solidity-security-candidates';

const pending={path:'source-1/src/render.py',query:'render',answer:'html_reflection'};
assert.deepEqual(controllerOwnedNextAction({
  action:['verify_source'],path:[pending.path],query:[pending.query],answer:[pending.answer]
},pending),{action:'verify_source',...pending});
assert.deepEqual(controllerOwnedNextAction({
  action:['read_file'],path:['source-1/src/http_handler.py']
}),{action:'read_file',path:'source-1/src/http_handler.py',query:'',answer:'',offset:0});
assert.equal(controllerOwnedNextAction({action:['read_file','final'],path:['x']},null),null);
assert.equal(controllerOwnedNextAction({action:['verify_source'],path:['x'],query:['y'],answer:['z']},pending),null);
assert.deepEqual(controllerOwnedNextAction({
  action:['read_solidity'],path:['source-1/Vault.sol'],query:['Vault.withdraw']
}),{action:'read_solidity',path:'source-1/Vault.sol',query:'Vault.withdraw',answer:'',offset:0});
assert.deepEqual(controllerOwnedNextAction({
  action:['read_solidity'],path:['source-1/src/handler.py'],query:['handler']
}),{action:'read_file',path:'source-1/src/handler.py',query:'',answer:'',offset:0});
assert.deepEqual(controllerOwnedNextAction({
  action:['search_files'],path:['source-1'],query:['withdraw']
}),{action:'search_files',path:'source-1',query:'withdraw',answer:'',offset:0});
assert.deepEqual(controllerOwnedNextAction({
  action:['list_files'],path:['source-1']
}),{action:'list_files',path:'source-1',query:'',answer:'',offset:0});
assert.equal(controllerOwnedNextAction({action:['read_solidity'],path:['source-1/Vault.sol']},null),null,
  'controller must not invent a missing function selector');
assert.equal(controllerOwnedNextAction({action:['plan_probe']},null),null,
  'controller must not fabricate a probe for unresolved model hypotheses');
assert.equal(canonicalSourceNavigationAction({
  action:'read_solidity',path:'source-1/src/http-handler.cjs',query:'x',answer:''
}).action,'read_file');
assert.equal(canonicalSourceNavigationAction({
  action:'outline_solidity',path:'source-1/Contract.sol',query:'',answer:''
}).action,'outline_solidity');
const focusedWorkflow=new InvestigationWorkflow();
const verifiedCase='b'.repeat(64);
focusedWorkflow.read('source-1/src/render.py');
focusedWorkflow.observe({
  action:'verify_source',path:'source-1/src/render.py',query:'render',answer:'html_reflection'
} as any,JSON.stringify({status:'behavior_observed',behavior_observed:true,caseId:verifiedCase}));
assert.equal(focusedWorkflow.focusVerifiedEvidence('c'.repeat(64)),false,
  'never focus an unrecorded model-invented case');
assert.equal(focusedWorkflow.focusVerifiedEvidence(verifiedCase),true);
focusedWorkflow.requireSource('source-1/src/http_handler.py');
assert.deepEqual(await focusedWorkflow.constraints(),{
  action:['read_file'],path:['source-1/src/http_handler.py']
});
focusedWorkflow.read('source-1/src/http_handler.py');
assert.deepEqual(await focusedWorkflow.constraints(),{action:['final']},
  'after source-backed caller reading, Qwen cannot navigate another target');
const nestedWorkflow=new InvestigationWorkflow();
nestedWorkflow.read('source-1/src/pipeline.py');
nestedWorkflow.observe({action:'verify_source',path:'source-1/src/pipeline.py',
  query:'wrap_fragment',answer:'html_reflection'} as any,
  JSON.stringify({status:'behavior_observed',behavior_observed:true,caseId:verifiedCase}));
assert.ok(nestedWorkflow.focusVerifiedEvidence(verifiedCase));
nestedWorkflow.requireSources(['source-1/src/renderer.py','source-1/src/http_handler.py']);
assert.deepEqual(await nestedWorkflow.constraints(),{
  action:['read_file'],path:['source-1/src/renderer.py']
});
nestedWorkflow.read('source-1/src/renderer.py');
assert.deepEqual(await nestedWorkflow.constraints(),{
  action:['read_file'],path:['source-1/src/http_handler.py']
});
nestedWorkflow.read('source-1/src/http_handler.py');
assert.deepEqual(await nestedWorkflow.constraints(),{action:['final']});
const jsHint=guidedSourceProbe('source-1/src/pipeline.cjs',
  'exports.wrapFragment=function wrapFragment(value){return "<p>"+value+"</p>";};');
assert.equal(jsHint?.functionName,'wrapFragment');
assert.equal(jsHint?.kind,'html_reflection');



const root=await mkdtemp(join(tmpdir(),'lotus-controller-facts-'));
try {
  await mkdir(join(root,'source-1','src'),{recursive:true});
  await writeFile(join(root,'source-1','src','renderer.py'),
    'def render(value):\n    return "<p>" + value + "</p>"\n');
  await writeFile(join(root,'source-1','src','http_handler.py'),
    'from renderer import render\n\ndef responseBody(userInput):\n    return render(userInput)\n');
  const evidence=await sourceCandidateEvidence(root,[{
    path:'source-1/src/renderer.py',name:'render',offset:0,line:1,signature:'def render(value)',
    probeHint:'candidate',callers:[{path:'source-1/src/http_handler.py',line:4}]
  }]);
  assert.equal(evidence.citations.length,2);
  assert.equal(evidence.citations[0].code,'def render(value):');
  assert.match(evidence.citations[1].code,/render\(userInput\)/);
  assert.equal(evidence.kind,'source_citations_not_findings');
  const unsupported=await sourceCandidateEvidence(root,[{
    path:'../../etc/passwd',name:'fake',offset:0,line:1,signature:'',probeHint:'',
    callers:[{path:'source-1/src/absent.py',line:1}]
  }]);
  assert.deepEqual(unsupported.citations,[]);
  const caseId='a'.repeat(64);
  const summary=verifiedProbeSummary([[caseId,{
    spec:{file:'src/renderer.py',function:'render',kind:'html_reflection'},
    result:{behavior_observed:true,observations:{attack_output:'<p><em>payload</em></p>'}}
  }]]);
  assert.ok(summary.includes(caseId));
  assert.ok(summary.includes('attack_output'));
  assert.match(summary,/impact and reachability unproven/i);
  assert.match(verifiedProbeSummary([]),/No successful reproduction/);
  // Real chained source lines, without claiming inferred exploitability.
  await writeFile(join(root,'source-1','src','pipeline.py'),
    'from src.codec import encode_fragment\ndef wrap_fragment(value):\n    return "<p>" + encode_fragment(value) + "</p>"\n');
  await writeFile(join(root,'source-1','src','codec.py'),
    'def encode_fragment(value):\n    return value\n');
  await writeFile(join(root,'source-1','src','renderer.py'),
    'from src.pipeline import wrap_fragment\ndef render(value):\n    return wrap_fragment(value)\n');
  const pythonTrace=await traceSourceCalls(join(root,'source-1'),'src/renderer.py','render');
  assert.ok(pythonTrace.facts.some(f=>f.source.includes('wrap_fragment(value)')));
  assert.ok(pythonTrace.facts.some(f=>f.path.endsWith('codec.py')),'Python imported helpers must be traced');
  await writeFile(join(root,'source-1','src','renderer.cjs'),
    'const {wrapFragment}=require("./pipeline.cjs");\nexports.render=function render(value){return wrapFragment(value);};\n');
  await writeFile(join(root,'source-1','src','pipeline.cjs'),
    'exports.wrapFragment=function wrapFragment(value){return "<p>"+value+"</p>";};\n');
  const jsTrace=await traceSourceCalls(join(root,'source-1'),'src/renderer.cjs','render');
  assert.ok(jsTrace.facts.some(f=>f.path.endsWith('pipeline.cjs')),'JS CommonJS helper must be traced');
  await writeFile(join(root,'source-1','src','Renderer.java'),
    'public class Renderer {\npublic static String render(String value){return Pipeline.wrapFragment(value);}\n}\n');
  await writeFile(join(root,'source-1','src','Pipeline.java'),
    'public class Pipeline {\npublic static String wrapFragment(String value){return value;}\n}\n');
  const javaTrace=await traceSourceCalls(join(root,'source-1'),'src/Renderer.java','Renderer.render');
  assert.ok(javaTrace.facts.some(f=>f.path.endsWith('Pipeline.java')),'Java helper must be traced');
  // Level 5 uses 144 source files: a 128-file map silently discarded 16.
  const manyFiles:string[]=[];
  for(let i=0;i<144;i++) {
    const file='source-1/src/module_'+i+'.py';
    manyFiles.push(file);
    await writeFile(join(root,file),'def function_'+i+'(value):\n    return value\n');
  }
  const map=await buildSourceMap(root,manyFiles);
  assert.equal(map.scannedFiles,144,'controller must index the entire 144-file challenge');
  assert.equal(map.skippedFiles,0);
  const authSource='pragma solidity ^0.8.20;\n'+
    'contract Authority {\naddress public administrator;address public operator;\n'+
    'constructor(){administrator=msg.sender;operator=msg.sender;}\n'+
    'function rotateOperator(address next) external {require(next!=address(0),"zero");operator=next;}\n'+
    'function changeAdministrator(address next) external {require(msg.sender==administrator,"admin");administrator=next;}\n}';
  const consumerSource='pragma solidity ^0.8.20;contract Vault {\n'+
    'address public operator; function settle() external {require(msg.sender==operator,"operator only");}\n}';
  await writeFile(join(root,'source-1','Authority.sol'),authSource);
  const risk=privilegedRoleMutationCandidate('source-1/Authority.sol',authSource,[authSource,consumerSource]);
  assert.equal(risk?.selector,'Authority.rotateOperator','unguarded role mutation is a controller candidate');
  assert.equal(privilegedRoleMutationCandidate('source-1/Authority.sol',authSource,[authSource]),null,
    'lack of a source-proven privileged role consumer cannot create a security candidate');
  const safeSource=authSource.replace('require(next!=address(0),"zero");operator=next;',
    'require(msg.sender==administrator,"admin");operator=next;');
  assert.equal(privilegedRoleMutationCandidate('source-1/Authority.sol',safeSource,[safeSource,consumerSource]),null,
    'explicit authorization guard must suppress the candidate');
  const solidityIndex=new SoliditySourceIndex(root);
  const abi=await solidityIndex.probeMenu(join(root,'source-1','Authority.sol'),64);
  assert.ok(abi.some(entry=>entry.selector==='Authority.operator'&&entry.operation==='call'),
    'public state getter is a real Solidity ABI function');
  const baseline=buildBaselineSequence(abi,'Authority.rotateOperator',true);
  assert.ok(baseline);
  assert.equal(baseline.steps[0].function,'operator()');
  assert.equal(baseline.steps[1].operation,'send');
  assert.equal((baseline.steps[1] as {sender?:number}).sender,1);
  assert.deepEqual(baseline.steps[1].args,['$account2']);
  console.log('Controller owned-next-action, grounded source citations and verified probe memory PASSED');
} finally {await rm(root,{recursive:true,force:true});}
