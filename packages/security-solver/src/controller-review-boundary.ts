/** Shared, language-neutral factual authority for independent review.
 *
 * The reviewer can dispute security significance, but cannot erase an
 * independently replayed observation or invent a mitigation, content type,
 * or source route. The same contract applies to all supported languages.
 * These checks NEVER approve a finding or authorize an external submission.
 */
import type {ReviewEvidence} from './review-evidence-chain';
import {entryReplayFacts,type EntryReviewObservation} from './entry-review-evidence';
import {roleConsumerImpactSequence,roleConsumerImpactObserved} from './controller-solidity-consumer-impact';

export interface ControllerReviewGrounds {
  sourceDigest:string;
  language:string;
  verifiedLocalEntryInjection:boolean;
  independentlyReplayed:boolean;
  replayedProbeKind:string|null;
  immutableFacts:string[];
  unresolvedQuestions:string[];
  // Only observed or source-cited blockers can be used as factual grounds.
  sourceBackedTextOnlyResponse:string[];
  sourceBackedEscaping:string[];
}
const lineRef=(file:string,line:number)=>file+':'+line;
const escapingOperation=/(?:\breplace\s*\(\s*['"][<>&]['"]\s*,\s*['"]&(?:lt|gt|amp);|\b(?:escapeHtml|encodeForHTML|StringEscapeUtils\.escapeHtml|html\.escape|markupsafe\.escape)\s*\()/i;
const explicitlyPlainText=/\btext\/plain\b/i;

/** Produce a finite list of provenance-cited facts, not narrative guesses. */
export function controllerReviewGrounds(evidence:ReviewEvidence,
  entry:EntryReviewObservation|null|undefined,
  replay?:{status?:string;behavior_observed?:boolean;kind?:string;observations?:unknown}|null):ControllerReviewGrounds {
  const proof=entryReplayFacts(entry);
  const verified=!!proof;
  const independentlyReplayed=!!replay && !!replay.observations &&
    ['behavior_observed','observation_only'].includes(replay.status||'');
  const escaped=evidence.links.filter(link=>escapingOperation.test(link.code))
    .map(link=>lineRef(link.file,link.line));
  const plain=evidence.links.filter(link=>explicitlyPlainText.test(link.code))
    .map(link=>lineRef(link.file,link.line));
  const immutableFacts=[
    'Source-backed evidence digest '+evidence.sourceDigest+' ('+evidence.language+')',
    ...evidence.links.map(link=>lineRef(link.file,link.line)+': '+link.code.trim()).slice(0,70),
    ...(verified?['Independent sandbox entry replay preserved the exact attacker-chosen HTML markup in the handler output.']:[]),
    ...(independentlyReplayed?['Independent sandbox replay recorded '+replay!.status+' for '+(replay!.kind||evidence.kind)+'.']:[])
  ];
  return {
    sourceDigest:evidence.sourceDigest,language:evidence.language,
    verifiedLocalEntryInjection:verified,independentlyReplayed,
    replayedProbeKind:independentlyReplayed ? replay?.kind||evidence.kind:null,
    immutableFacts,
    unresolvedQuestions:[
      'Deployment, browser interpretation and external exploitability remain unproven unless separately established.',
      ...evidence.unresolved.slice(0,6)
    ],
    sourceBackedTextOnlyResponse:plain,sourceBackedEscaping:escaped
  };
}

export interface ReviewGroundClaim {
  verdict:string;
  issues:Array<{severity:string;category:string;description:string}>;
  reasoning:string;
}
/**
 * Enforce the distinction between facts and an independent technical opinion.
 * When a replay proved unescaped attacker-selected HTML at a source-declared
 * entry, a negative factual claim needs a relevant, exact source citation.
 * An absence of deployed/browser evidence can limit impact but cannot erase
 * the locally executed entry-to-output path.
 */
export function controllerReviewGroundDefect(
  decision:ReviewGroundClaim,grounds:ControllerReviewGrounds
):string|null {
  if(decision.verdict!=='reject')return null;
  if(grounds.independentlyReplayed) {
    const prose=decision.issues.map(x=>x.description).join(' ' )+' '+decision.reasoning;
    if(/\b(?:no (?:supported|executed|recorded|successful) (?:probe|test|reproduction)|nothing (?:was |has been )?reproduced|no (?:runtime )?observation)\b/i.test(prose))
      return 'The independent controller replay recorded the executed probe and its actual observations. A rejection must assess security significance without denying the completed test.';
  }
  if(!grounds.verifiedLocalEntryInjection)return null;
  const fatal=decision.issues.filter(x=>x.severity==='fatal');
  if(!fatal.length)return 'A technical rejection requires a fatal, evidence-backed technical ground.';
  const cited=(text:string)=>grounds.immutableFacts.some(fact=>{
    const m=/^(.+:\d+): /.exec(fact);
    return !!m && text.includes(m[1]);
  });
  for(const issue of fatal){
    const claim=issue.description;
    const whole=claim+' '+decision.reasoning;
    const saysEscaped=/\b(?:saniti[sz](?:e[ds]?|ation)|html[- ]?escap(?:ed|ing)|encoded(?: as)? (?:safe|html)|injection (?:prevented|blocked))\b/i.test(claim);
    const saysPlain=/\btext\/plain\b|\bplain[- ]text (?:http )?(?:response|content type)\b/i.test(claim);
    const deniesObserved=/\b(?:no (?:input.to.output|input.to.sink)|not (?:reflected|returned|preserved)|no (?:attacker|user)[- ]controlled input|input not (?:controlled|reflected))\b/i.test(claim);
    if(deniesObserved)
      return 'The independently replayed entry case proves the exact attacker-selected markup was preserved in the handler output. An unsupported denial of the observed local input/output path is invalid.';
    if(saysEscaped && grounds.sourceBackedEscaping.length===0)
      return 'The source-backed controller facts contain no executed escaping/encoding basis for this rejection. The independent entry replay returned unescaped markup. Identify a real mitigation and its exact source line.';
    if(saysPlain && grounds.sourceBackedTextOnlyResponse.length===0)
      return 'The recorded source contains no source-backed text/plain output declaration; do not infer it from a String return. Cite a real content-type declaration.';
    // The reviewer is permitted to cite actual source-backed mitigations.
    // But a mere guessed network or browser limitation cannot overturn
    // the observed source-level behavior without any source-cited blocker.
    const allegesPositiveBlocker=/\b(?:is|was|are|has been|clearly|actually|explicitly)\b.{0,70}\b(?:unreachable|unregistered|not wired|never called|discarded|scope[- ]excluded|inert)\b/i.test(claim);
    if(allegesPositiveBlocker && !cited(whole))
      return 'This rejection asserts an actual source-level blocker without citing a controller-recorded file:line. Supply the exact source line, or distinguish unknown deployment/context from a proved blocker.';
    // Untrusted means unsafe to assume, not a verified negative security ground.
    if(/\b(?:untrusted|not trusted)\b/i.test(claim) &&
       /\b(?:no (?:security )?(?:issue|risk|impact|vulnerability)|safe|harmless|not vulnerable)\b/i.test(whole) &&
       !cited(whole))
      return 'Untrusted input cannot be a mitigating control. Independently replayed entry-to-HTML facts require a specific source-backed blocker, not a claim that lack of trust makes the output safe.';
  }
  return null;
}


/** Controller-owned technical review of an independently replayed *local*
 * source-level HTML injection. This is a narrow, factual classification:
 * it does not assert XSS, a deployed HTTP route, authorization bypass,
 * policy eligibility or an externally reportable vulnerability.
 *
 * When every predicate below is true the actual unescaped markup injection
 * is not a discretionary model opinion. A verified external impact still
 * requires additional evidence; recommendation is always dont_submit.
 */
export function controllerVerifiedLocalHtmlReview(
  grounds:ControllerReviewGrounds,
  entry:EntryReviewObservation|null|undefined
) {
  if(!grounds.verifiedLocalEntryInjection || !grounds.independentlyReplayed ||
     grounds.replayedProbeKind!=='html_reflection' ||
     grounds.sourceBackedTextOnlyResponse.length ||
     grounds.sourceBackedEscaping.length)return null;
  const obs=entry?.observations;
  if(!obs)return null;
  const {control_input:normal,control_output:control,
    attack_input:attack,attack_output:output}=obs;
  if(!normal || !control || !attack || !output ||
     control===output || !control.includes(normal) ||
     !attack.startsWith('<') || !/<\/?[a-z][^>]*>/i.test(attack) ||
     !output.includes(attack) || output===attack)return null;
  // The independently reproduced handler must demonstrably construct or
  // return HTML markup in its cited source, not merely an arbitrary string.
  const sourceConstructsHtml=grounds.immutableFacts.some(line=>
    /^.+:\d+: /.test(line) &&
    /(?:['"\x60]<(?:p|div|span|article|section|body|html|em|strong)\b|text\/html\b|innerHTML\b|document\.write\b)/i.test(line));
  if(!sourceConstructsHtml)return null;
  return {
    verdict:'approve' as const,recommendation:'dont_submit' as const,
    severity:'low' as const,confidence:0.72,bet100:false,
    ratingReason:'Independent controller replay verified a source-declared handler returning attacker-selected raw HTML markup in a constructed HTML fragment; external client rendering and exploitability remain unproven.',
    rubric:{exploitability:1,impactSeverity:1,evidenceQuality:3,novelty:0,scopeAlignment:2},
    issues:[{category:'evidence_limit',severity:'warning' as const,
      description:'Only source-level entry-to-HTML injection is established. Deployed routing, output content type, browser behavior, and external exploitation remain unverified.'}],
    reasoning:'The controller independently re-executed the recorded case and the entry handler, observed differential control and attacker-selected HTML passing into constructed markup, and verified the cited source chain. This technically verifies the local injection, not browser script execution or a reportable external impact. External submission is prohibited pending further evidence.'
  };
}

/** An independent replay can establish a local privileged-consumer
 * authorization failure without asking a language model to reconstruct
 * transaction order. The source, exact declared sequence, full EVM receipts,
 * and already-validated direct transaction must all agree. This authorizes
 * neither a claim about deployment nor an external bounty submission.
 */
export function controllerVerifiedLocalSolidityConsumerReview(input:{
 source:string;selector:string;sequence:unknown;
 replay:{status?:string;kind?:string;behavior_observed?:boolean;observations?:unknown}
}) {
  const {source,selector,sequence,replay}=input;
  if(replay.status!=='behavior_observed'||replay.kind!=='solidity_sequence'||
     replay.behavior_observed!==true||!sequence||typeof sequence!=='object')return null;
  const mutator=selector.split('.').at(-1)||'';
  if(!/^[A-Za-z_]\w*$/.test(mutator))return null;
  const declaration=new RegExp('\\bfunction\\s+'+mutator+'\\s*\\([^)]*\\)[^{]*\\{').exec(source);
  if(!declaration)return null;
  const bodyStart=declaration.index+declaration[0].length;
  const close=source.indexOf('}',bodyStart);
  if(close<0||close-bodyStart>2600)return null;
  const assigned=/\b(operator|owner|administrator|admin|manager|guardian|controller|authority)\s*=\s*[A-Za-z_]\w*\s*;/i.exec(source.slice(bodyStart,close));
  if(!assigned)return null;
  const role=assigned[1];
  const expected=roleConsumerImpactSequence(source,role,mutator);
  if(!expected || JSON.stringify(expected)!==JSON.stringify(sequence) ||
     !roleConsumerImpactObserved(replay.observations,role,mutator))return null;
  return {
    verdict:'approve' as const,recommendation:'dont_submit' as const,
    severity:'low' as const,confidence:0.78,bet100:false,
    ratingReason:'Independent EVM replay confirmed a role-gated operation denied to an account before a nonadministrator role mutation, then allowed to that account after mutation, with a measured beneficiary balance increase. Actual deployment impact is unverified.',
    rubric:{exploitability:2,impactSeverity:1,evidenceQuality:3,novelty:0,scopeAlignment:2},
    issues:[{category:'evidence_limit',severity:'warning' as const,
      description:'Verified on a fresh isolated EVM. Actual deployment configuration, privileges, upgrade/proxy behavior and off-chain impact are not established.'}],
    reasoning:'A source-declared privilege guard, identical authorization-sensitive operation, expected initial revert, nonadministrator role mutation, subsequent successful operation, and changed state were independently replayed from the exact recorded declarative sequence. This technically verifies the local authorization consequence but does not establish a live-chain exploit or authorize submission.'
  };
}
