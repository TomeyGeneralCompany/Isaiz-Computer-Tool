/** Offline controller/reviewer regression: evidence facts and rejection gates.
 * No model, external network or benchmark answer key is required.
 */
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {buildReviewEvidence,reviewRejectionDefect} from '../packages/security-solver/src/review-evidence-chain';

const root=await mkdtemp(join(tmpdir(),'lotus-review-chain-'));
const java='src/main/java/org/fixture/';
try {
  await mkdir(join(root,java),{recursive:true});
  await writeFile(join(root,java,'HttpHandler.java'),
    'package org.fixture;\npublic class HttpHandler {\npublic String responseBody(String userInput){return Renderer.render(userInput);}\n}');
  await writeFile(join(root,java,'Renderer.java'),
    'package org.fixture;\npublic class Renderer {\npublic static String render(String value){return Pipeline.wrapFragment(value);}\n}');
  await writeFile(join(root,java,'Pipeline.java'),
    'package org.fixture;\npublic class Pipeline {\npublic static String wrapFragment(String value){return "<p>"+Codec.encodeFragment(value)+"</p>";}\n}');
  await writeFile(join(root,java,'Codec.java'),
    'package org.fixture;\npublic class Codec {\npublic static String encodeFragment(String value){return value;}\n}');
  const input={testedFile:java+'Renderer.java',testedFunction:'Renderer.render',
    callerFile:java+'HttpHandler.java',callerLine:3,kind:'html_reflection',reachability:'caller'};
  const evidence=await buildReviewEvidence(root,input);
  assert.equal(evidence.language,'java');
  for(const file of ['HttpHandler.java','Renderer.java','Pipeline.java','Codec.java'])
    assert.ok(evidence.links.some(x=>x.file.endsWith(file)),file+' must be included');
  assert.ok(evidence.summary.includes('return value;'),'actual helper behavior must appear');
  assert.ok(evidence.summary.includes('userInput'),'caller input must be supplied');
  assert.ok(!evidence.reachabilityRequirement.includes('transaction is required'));
  const reject=(reason:string)=>({verdict:'reject',reasoning:reason,
    issues:[{severity:'fatal',category:'reachability',description:reason}]});
  assert.match(reviewRejectionDefect(reject('No production transaction path was shown'),evidence)??'',/Transaction-chain/);
  assert.match(reviewRejectionDefect(reject('Local test only; not deployed'),evidence)??'',/local reproduction/i);
  assert.match(reviewRejectionDefect(reject('An effective sanitizer escapes the output at src/main/java/org/fixture/Codec.java:3'),evidence)??'',/no source-backed sanitization/,
    'the reviewer must not mistake a helper name for actual escaping');
  assert.match(reviewRejectionDefect(reject('Not enough proof'),evidence)??'',/Fatal rejection/);
  assert.equal(reviewRejectionDefect({verdict:'approve',issues:[],reasoning:'Supported by source'},evidence),null);
  const repeated=await buildReviewEvidence(root,input);
  assert.equal(evidence.sourceDigest,repeated.sourceDigest,'verified facts are deterministic and persistent');

  // The controller must not classify a mitigated candidate as vulnerable just
  // because the same call graph exists. Reviewer still checks mitigation.
  await writeFile(join(root,java,'Codec.java'),
    'package org.fixture;\npublic class Codec {\npublic static String encodeFragment(String value){return value.replace("&","&amp;").replace("<","&lt;");}\n}');
  const escaped=await buildReviewEvidence(root,input);
  assert.ok(escaped.summary.includes('replace("<","&lt;")'));
  assert.notEqual(escaped.sourceDigest,evidence.sourceDigest,'changed mitigations must change verified evidence');
  assert.equal(reviewRejectionDefect(reject('Effective escaping in src/main/java/org/fixture/Codec.java:3 prevents raw markup reflection'),escaped),null);

  await writeFile(join(root,'Contract.sol'),'contract Contract { function settle() public {} }\n');
  const solidity=await buildReviewEvidence(root,{
    testedFile:'Contract.sol',testedFunction:'Contract.settle',callerFile:'Contract.sol',
    callerLine:1,kind:'solidity_sequence',reachability:'direct_transaction'});
  assert.equal(solidity.language,'solidity');
  assert.match(solidity.reachabilityRequirement,/transaction/);
  assert.equal(reviewRejectionDefect(reject('Missing transaction sequence and state changes'),solidity),null);
  console.log('Controller source-chain persistence, language-specific reachability and rejection gates PASSED');
}finally{await rm(root,{recursive:true,force:true});}
