import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {controllerOwnedNextAction,canonicalSourceNavigationAction} from '../packages/security-solver/src/controller-next-action';
import {sourceCandidateEvidence,verifiedProbeSummary} from '../packages/security-solver/src/source-candidate-evidence';

const pending={path:'source-1/src/render.py',query:'render',answer:'html_reflection'};
assert.deepEqual(controllerOwnedNextAction({
  action:['verify_source'],path:[pending.path],query:[pending.query],answer:[pending.answer]
},pending),{action:'verify_source',...pending});
assert.deepEqual(controllerOwnedNextAction({
  action:['read_file'],path:['source-1/src/http_handler.py']
}),{action:'read_file',path:'source-1/src/http_handler.py',query:'',answer:'',offset:0});
assert.equal(controllerOwnedNextAction({action:['read_file','final'],path:['x']},null),null);
assert.equal(controllerOwnedNextAction({action:['verify_source'],path:['x'],query:['y'],answer:['z']},pending),null);
assert.equal(controllerOwnedNextAction({action:['plan_probe']},null),null,
  'controller must not fabricate a probe for unresolved model hypotheses');
assert.equal(canonicalSourceNavigationAction({
  action:'read_solidity',path:'source-1/src/http-handler.cjs',query:'x',answer:''
}).action,'read_file');
assert.equal(canonicalSourceNavigationAction({
  action:'outline_solidity',path:'source-1/Contract.sol',query:'',answer:''
}).action,'outline_solidity');

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
  console.log('Controller owned-next-action, grounded source citations and verified probe memory PASSED');
} finally {await rm(root,{recursive:true,force:true});}
