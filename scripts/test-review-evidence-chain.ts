/** Offline controller/reviewer regression: evidence facts and rejection gates.
 * No model, external network or benchmark answer key is required.
 */
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {execFileSync} from 'node:child_process';
import {buildReviewEvidence,reviewRejectionDefect} from '../packages/security-solver/src/review-evidence-chain';
import {entryReplayFacts,entryReviewRejectionDefect} from '../packages/security-solver/src/entry-review-evidence';
import {controllerProofCandidate} from '../packages/security-solver/src/controller-proof-candidate';

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

  assert.equal(reviewRejectionDefect(reject(
    'This caller does not sanitize the input and there is no effective escaping in Codec.encodeFragment; executable browser impact still requires source-backed evidence.'),evidence),
    null,'negative sanitizer claim must not trigger early false-positive assertion detector');
  assert.equal(reviewRejectionDefect(reject(
    'No effective sanitizer was observed in the return path; downstream rendering context remains unproven.'),evidence),
    null,'absence of escaping is not a positive mitigation claim');


  assert.match(reviewRejectionDefect(reject(
    'The browser does not execute the HTML. The Codec.encodeFragment method returns the input unchanged, so there is no sanitization. Output is only reflected as plain text.'),evidence)??'',
    /inert browser|HTML rendering context/,
    'unobserved browser inertness must not be stated as a fact');
  assert.equal(reviewRejectionDefect(reject(
    'The isolated source-level reflection does not establish JavaScript execution; actual downstream rendering context and attacker control still need to be established.'),evidence),
    null,'an evidence-limited review must be allowed to reject unproven executable impact');

  assert.match(reviewRejectionDefect(reject(
    'No effective input sanitization or escaping occurs; Codec.encodeFragment returns the input unmodified, so there is no actual security risk.'),evidence)??'',/Returning unescaped user data|Identity transformation is not sanitization/,
    'identity encoder is not a security mitigation; reviewer must name a real missing link');

  // Level5 Python #42100919715: reviewer falsely called a pass-through
  // codec a sanitizer even though the observed HTML was returned unescaped.
  const pythonIdentity={...evidence,language:'python'};
  assert.match(reviewRejectionDefect(reject(
    'The codec.py implementation (encode_fragment) returns the input value without modification, acting as a sanitizer that preserves the input. This prevents HTML injection as the output is the raw input wrapped in HTML tags, not unescaped HTML.'),pythonIdentity)??'',
    /Identity transformation is not sanitization/,
    'identity-returning helpers must never be treated as an effective sanitizer');
  assert.match(reviewRejectionDefect(reject(
    'The downstream consumer has a source-verified text/plain response and cannot interpret markup.'),pythonIdentity)??'',
    /no source-backed text/,
    'a claimed text/plain response must be backed by a real source line, not by reviewer assertion');
  // Regressions from the real post-#146 Level 5 Python/Java run: a
  // pass-through codec is not a sanitizer and string return != text/plain.
  assert.match(reviewRejectionDefect(reject(
    'The codec returns the input value without modification, acting as a sanitizer. This prevents HTML injection.'),evidence)??'',/Identity transformation is not sanitization/,
    'a reviewer cannot turn return value into an effective sanitizer');
  assert.match(reviewRejectionDefect(reject(
    'The output is a text/plain response, not HTML. The handler does not render in a browser.'),evidence)??'',/no source-backed text\/plain/,
    'a reviewer cannot invent an HTTP content type from a Java String');
  assert.equal(reviewRejectionDefect(reject(
    'The returned markup reaches no demonstrated browser rendering sink and the caller has no documented externally deployed route.'),evidence),
    null,'real limits must remain legitimate independent review grounds');
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

  // Independent review must see the real upstream request entry point,
  // not only the locally reproduced helper and its first direct caller.
  await mkdir(join(root,'src','web'),{recursive:true});
  await writeFile(join(root,'src','web','pipeline.cjs'),
    'exports.wrapFragment=function wrapFragment(value){return "<p>"+value+"</p>";};\n');
  await writeFile(join(root,'src','web','renderer.cjs'),
    'const {wrapFragment}=require("./pipeline.cjs");\nexports.render=function render(value){return wrapFragment(value);};\n');
  await writeFile(join(root,'src','web','http-handler.cjs'),
    'const {render}=require("./renderer.cjs");\nexports.responseBody=function responseBody(url){\n'+
    'const userText=new URL(url,"http://localhost").searchParams.get("message")||"";\n'+
    'return render(userText);};\n');
  execFileSync('git',['init','-q',root]);
  execFileSync('git',['-C',root,'add','.']);
  const jsReview=await buildReviewEvidence(root,{
    testedFile:'src/web/pipeline.cjs',testedFunction:'wrapFragment',
    callerFile:'src/web/renderer.cjs',callerLine:2,
    kind:'html_reflection',reachability:'caller'});
  // Include the true helper body, not merely its reassuring encoder name.
  await writeFile(join(root,'src','web','codec.cjs'),
    'exports.encodeFragment=function encodeFragment(value){return value;};\n');
  await writeFile(join(root,'src','web','pipeline.cjs'),
    'const {encodeFragment}=require("./codec.cjs");\n'+
    'exports.wrapFragment=function wrapFragment(value){return "<p>"+encodeFragment(value)+"</p>";};\n');
  const jsDownstream=await buildReviewEvidence(root,{
    testedFile:'src/web/renderer.cjs',testedFunction:'render',
    callerFile:'src/web/http-handler.cjs',callerLine:4,
    kind:'html_reflection',reachability:'caller'});
  assert.ok(jsDownstream.links.some(link=>link.file==='src/web/codec.cjs' &&
    link.code.includes('return value;')),
    'independent reviewer must see the actual identity encoder implementation');
  assert.ok(jsDownstream.summary.includes('encodeFragment(value)'),
    'independent reviewer must see the multi-hop JavaScript call graph');
  assert.ok(jsReview.links.some(link=>link.file.endsWith('http-handler.cjs') &&
    link.code.includes('searchParams.get')),
    'reviewer must receive the actual externally controlled request-to-render path');
  assert.match(jsReview.summary,/new URL\(/);
  assert.match(reviewRejectionDefect(reject('Only hardcoded test input; no attacker input can reach the sink'),jsReview)??'',/request-parameter extraction/,
    'Independent review must not mistake fixed probe strings for hardcoded application input');
  assert.match(reviewRejectionDefect(reject(
    'The input is parsed via URL.searchParams.get("message") and explicitly validated by the caller; it is sanitized by the application context.'),jsReview)??'',
    /parser extracts input|source-backed escaping/,
    'query parsing is not output escaping or evidence of caller validation');


  assert.equal(reviewRejectionDefect(reject(
    'URL.searchParams.get parses the query but does not sanitize, validate or HTML-escape it; the input-to-HTML chain requires an independently supported attacker-controlled sink.'),jsReview),
    null,'a review denying parser sanitization must not be rejected repeatedly');
  assert.match(reviewRejectionDefect(reject(
    'URL.searchParams.get validates the parameter and sanitizes the user text before renderer.'),jsReview)??'',
    /parser extracts input|no source-backed sanitization/,'positive unsupported parser sanitization assertion must be corrected');
  assert.equal(reviewRejectionDefect(reject(
    'The request parsing does not sanitize this input, but the downstream client renders only inert text, and there is no active HTML context demonstrated.'),jsReview),
    null,'source-grounded contextual objections must remain eligible for independent review');
  await writeFile(join(root,'Contract.sol'),'contract Contract { function settle() public {} }\n');
  const solidity=await buildReviewEvidence(root,{
    testedFile:'Contract.sol',testedFunction:'Contract.settle',callerFile:'Contract.sol',
    callerLine:1,kind:'solidity_sequence',reachability:'direct_transaction'});
  assert.equal(solidity.language,'solidity');
  assert.match(solidity.reachabilityRequirement,/transaction/);
  assert.equal(reviewRejectionDefect(reject('Missing transaction sequence and state changes'),solidity),null);

  // #138 end-to-end replay must be weighed as an executed entry-to-output
  // observation, not as an untested lexical handler reference. The reviewer
  // may reject unproven XSS/remote exploitation but must not negate observed
  // local attacker-selected input or falsely claim unescaped HTML was escaped.
  const entryCase={
    status:'behavior_observed',kind:'entry_html_reflection',behavior_observed:true,
    observations:{
      control_input:'TOMEY_CONTROL_abc',
      control_output:'<p>TOMEY_CONTROL_abc</p>',
      attack_input:'<em data-tomey="abc">TOMEY_PROBE</em>',
      attack_output:'<p><em data-tomey="abc">TOMEY_PROBE</em></p>',
      entry_parameter:'message',
      entry_control_url:'http://localhost/?message=TOMEY_CONTROL_abc',
      entry_attack_url:'http://localhost/?message=%3Cem%20data-tomey%3D%22abc%22%3ETOMEY_PROBE%3C%2Fem%3E'
    }
  };
  assert.match(entryReplayFacts(entryCase)||'',/executed the selected source-declared entry function/,
    'the entry case must establish executed request-controlled source-to-output evidence');
  const rejected=(reason:string)=>({verdict:'reject',reasoning:reason,
    issues:[{severity:'fatal',description:reason}]});
  assert.match(entryReviewRejectionDefect(rejected(
    'No attacker control over the output; there is no actual input-to-sink edge.'),entryCase)||'',
    /entry input control|input-to-output path/);
  assert.match(entryReviewRejectionDefect(rejected(
    'The source evidence shows that the input is sanitized by encodeFragment. The replay proves the attacker input is not reflected as-is.'),entryCase)||'',
    /returned the exact attacker-selected HTML marker unmodified/,
    'JavaScript reviewer may not infer sanitizer from a helper name against raw entry replay');
  assert.match(entryReviewRejectionDefect(rejected(
    'The response is HTML-escaped because the input is inside a <p> paragraph tag.'),entryCase)||'',
    /wrapping it in paragraph tags is not HTML escaping/);
  assert.match(entryReviewRejectionDefect(rejected(
    'This is not rendered in a context where markup could be interpreted and has no security-relevant output.'),entryCase)||'',
    /observed unescaped attacker-chosen HTML/);
  assert.match(entryReviewRejectionDefect(rejected(
    'The replay is limited to a local function behavior. The evidence does not prove attacker control in a deployed system and the reflection is observed in a controlled environment, not a deployed system.'),entryCase)||'',
    /Independent controller replay|Offline execution of an owned synthetic handler/);
  assert.match(entryReviewRejectionDefect(rejected(
    'The input is not trusted and the output is not a security-relevant context. The attacker input is not reaching a security-relevant output.'),entryCase)||'',
    /Independent controller replay|source-declared entry handler output/);
  assert.equal(entryReviewRejectionDefect(rejected(
    'The route is not registered or exposed, and the source shows no connection from this entry handler to a client.'),entryCase),null);
  assert.equal(entryReviewRejectionDefect(rejected(
    'The handler locally returns unescaped markup but the actual network route is not deployed and the scope excludes its only consumer.'),entryCase),
    null,'independent reviewer must retain authority to reject source-backed limitations');
  assert.equal(entryReviewRejectionDefect(rejected('No input reaches the sink.'),null),null,
    'never invent entry proof where the trusted replay is absent');
  const mitigatedEntry={...entryCase,behavior_observed:false,status:'behavior_not_observed'};
  assert.equal(entryReviewRejectionDefect(rejected('This source escapes HTML.'),mitigatedEntry),null,
    'effective escaping must not be bypassed by stale entry evidence');


  // Controller evidence belongs to the controller even if the small model
  // returns findings=[] or proposes the wrong case. This case is provisional:
  // the independent reviewer is still required to authorize its validity.
  const source='const {render}=require("./renderer.cjs");\nexports.responseBody=function responseBody(url){return render(url);};\n';
  const caseId='a'.repeat(64);
  const candidate=controllerProofCandidate({
    caseId,rendererFile:'source-1/src/renderer.cjs',rendererSelector:'render',
    callerFile:'source-1/src/http-handler.cjs',callerLine:2,callerSource:source,
    entryCase:{kind:'entry_html_reflection',behaviorObserved:true,
      observations:{control_input:'TOMEY_CONTROL_abc',
        control_output:'<p>TOMEY_CONTROL_abc</p>',
        attack_input:'<em data-tomey="abc">TOMEY_PROBE</em>',
        attack_output:'<p><em data-tomey="abc">TOMEY_PROBE</em></p>',
        entry_attack_url:'http://localhost/?message=malicious',
        entry_parameter:'message'}}});
  assert.equal(candidate?.caseId,caseId);
  assert.equal(candidate?.callerLine,2);
  assert.equal(candidate?.severity,'low');
  assert.match(candidate?.falsification||'',/content type/);
  assert.equal(controllerProofCandidate({
    caseId,rendererFile:'src/renderer.cjs',rendererSelector:'render',
    callerFile:'src/http-handler.cjs',callerLine:2,callerSource:source,
    entryCase:{kind:'entry_html_reflection',behaviorObserved:false,
      observations:{control_input:'normal',control_output:'normal',attack_input:'<em>X</em>',
        attack_output:'<em>X</em>'}}}),null,
    'a failed entry reproduction cannot be promoted into a finding');
  assert.equal(controllerProofCandidate({
    caseId,rendererFile:'src/renderer.cjs',rendererSelector:'render',
    callerFile:'src/http-handler.cjs',callerLine:2,
    callerSource:'line1\nnot_a_real_call_here();\n',
    entryCase:{kind:'entry_html_reflection',behaviorObserved:true,
      observations:{control_input:'normal',control_output:'normal',attack_input:'<em>X</em>',
        attack_output:'<em>X</em>'}}}),null,
    'the controller cannot claim an unrelated source line as an entry edge');

  console.log('Controller source-chain persistence, language-specific reachability and rejection gates PASSED');
}finally{await rm(root,{recursive:true,force:true});}
