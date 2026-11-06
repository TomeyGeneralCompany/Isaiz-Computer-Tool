import assert from 'node:assert/strict';
import {controllerReviewGrounds,controllerReviewGroundDefect,controllerVerifiedLocalHtmlReview} from '../packages/security-solver/src/controller-review-boundary';
import type {ReviewEvidence} from '../packages/security-solver/src/review-evidence-chain';

const entry={status:'behavior_observed',kind:'entry_html_reflection',
  behavior_observed:true,
  observations:{control_input:'NORMAL',control_output:'<p>NORMAL</p>',
    attack_input:'<em>ATTACKER</em>',attack_output:'<p><em>ATTACKER</em></p>'}};
const reject=(reason:string)=>({verdict:'reject',issues:[{severity:'fatal',category:'impact',description:reason}],reasoning:reason});
const approve={verdict:'approve',issues:[],reasoning:'Locally verified unescaped entry HTML'};
const examples=[
 {language:'java',file:'src/Handler.java',code:'return "<p>"+userInput+"</p>";'},
 {language:'python',file:'src/handler.py',code:'    return "<p>" + user_input + "</p>"'},
 {language:'javascript',file:'src/handler.js',code:'return "<p>"+userInput+"</p>";'},
 {language:'solidity',file:'src/Handler.sol',code:'function html(string memory value) public pure returns(string memory) {}'}
];
for(const ex of examples){
  const ev:ReviewEvidence={language:ex.language,kind:'html_reflection',
    reachabilityRequirement:'Observed handler input/output',
    sourceDigest:'f'.repeat(64),
    links:[{file:ex.file,line:12,relationship:'recorded caller context',code:ex.code}],
    unresolved:[],summary:'Observed caller source'};
  const facts=controllerReviewGrounds(ev,entry);
  assert.equal(facts.verifiedLocalEntryInjection,true,ex.language);
  assert.equal(facts.sourceBackedTextOnlyResponse.length,0,ex.language);
  assert.equal(controllerReviewGroundDefect(approve,facts),null,ex.language);
  assert.match(controllerReviewGroundDefect(reject('The handler output is a text/plain response.'),facts)||'',
    /no source-backed text\/plain/,ex.language);
  assert.match(controllerReviewGroundDefect(reject('No attacker-controlled input reaches the output.'),facts)||'',
    /independently replayed entry case/,ex.language);
  assert.match(controllerReviewGroundDefect(reject('The handler is explicitly unreachable and inert.'),facts)||'',
    /controller-recorded file:line/,ex.language);
  assert.match(controllerReviewGroundDefect(reject('The input is not trusted, so there is no security issue.'),facts)||'',
    /Untrusted input cannot be a mitigating control/,ex.language);
  const withoutEntry=controllerReviewGrounds(ev,null);
  assert.equal(withoutEntry.verifiedLocalEntryInjection,false);
  assert.equal(controllerReviewGroundDefect(reject('There is no proof of reachability.'),withoutEntry),null);
}
for(const lang of ['solidity','python','java','javascript']){
  const ev:ReviewEvidence={language:lang,kind:lang==='solidity'?'solidity_sequence':
    lang==='java'?'java_sequence':lang==='python'?'python_sequence':'javascript_sequence',
    reachabilityRequirement:'Source replay',sourceDigest:'c'.repeat(64),
    links:[{file:'src/Counter',line:5,code:'increment()',relationship:'observed sequence'}],
    unresolved:[],summary:'Verified local state observation'};
  const grounds=controllerReviewGrounds(ev,null,{
    status:'observation_only',behavior_observed:false,kind:ev.kind,
    observations:{steps:[{value:1},{value:2}]}});
  assert.equal(grounds.independentlyReplayed,true);
  assert.equal(grounds.replayedProbeKind,ev.kind);
  assert.match(controllerReviewGroundDefect(reject(
    'No supported probe was executed for this source.'),grounds)||'',
    /independent controller replay recorded the executed probe/,
    'every language must preserve independently replayed observations');
  assert.equal(controllerReviewGroundDefect(reject(
    'The state difference is observed but the source proves no unauthorized privilege boundary.'),grounds),null,
    'a real lack of security impact remains a valid reason to reject');
}
for(const ex of examples.slice(0,3)){
  const evidence:ReviewEvidence={language:ex.language,kind:'html_reflection',
    reachabilityRequirement:'Observed local entry-to-HTML injection',
    sourceDigest:'a'.repeat(64),summary:'Controller evidence',unresolved:[],
    links:[{file:ex.file,line:12,relationship:'source-declared entry',code:ex.code}]};
  const grounds=controllerReviewGrounds(evidence,entry,{
    status:'behavior_observed',behavior_observed:true,kind:'html_reflection',
    observations:{control_input:'NORMAL',control_output:'<p>NORMAL</p>',
      attack_input:'<em>ATTACKER</em>',attack_output:'<p><em>ATTACKER</em></p>'}});
  const decision=controllerVerifiedLocalHtmlReview(grounds,entry);
  assert.equal(decision?.verdict,'approve',ex.language);
  assert.equal(decision?.recommendation,'dont_submit',
    'controller-authored local technical finding is NOT an external bounty approval');
  assert.equal(decision?.severity,'low');
  assert.equal(decision?.bet100,false);
  assert.equal(controllerVerifiedLocalHtmlReview(grounds,{...entry,
    observations:{...entry.observations,attack_output:'<p>&lt;em&gt;ATTACKER&lt;/em&gt;</p>'}}),null,
    'escaped output must never be classified as raw HTML injection');
  const plain=controllerReviewGrounds({...evidence,links:[
    ...evidence.links,{file:ex.file,line:17,relationship:'header',
      code:'setContentType("text/plain");'}]},entry,{
    status:'behavior_observed',behavior_observed:true,kind:'html_reflection',
    observations:{control_input:'NORMAL',control_output:'<p>NORMAL</p>',
      attack_input:'<em>ATTACKER</em>',attack_output:'<p><em>ATTACKER</em></p>'}});
  assert.equal(controllerVerifiedLocalHtmlReview(plain,entry),null,
    'source-verified text/plain context blocks controller local HTML technical approval');
  assert.equal(controllerVerifiedLocalHtmlReview(
    controllerReviewGrounds(evidence,entry,null),entry),null,
    'a model assertion cannot replace independent reproduction');
}
const ev:ReviewEvidence={language:'java',kind:'html_reflection',reachabilityRequirement:'',
  sourceDigest:'e'.repeat(64),summary:'',unresolved:[],
  links:[{file:'src/HttpHandler.java',line:19,
    relationship:'handler',code:'response.setContentType("text/plain");'}]};
const facts=controllerReviewGrounds(ev,entry);
assert.deepEqual(facts.sourceBackedTextOnlyResponse,['src/HttpHandler.java:19']);
assert.equal(controllerReviewGroundDefect(reject('The response at src/HttpHandler.java:19 is text/plain.'),facts),null,
  'real source-backed content type is an admissible factual ground, not automatic approval');
console.log('Shared four-language immutable review fact boundary PASSED');
