/** Shared, language-neutral factual authority for independent review.
 *
 * The reviewer can dispute security significance, but cannot erase an
 * independently replayed observation or invent a mitigation, content type,
 * or source route. The same contract applies to all supported languages.
 * These checks NEVER approve a finding or authorize an external submission.
 */
import type {ReviewEvidence} from './review-evidence-chain';
import {entryReplayFacts,type EntryReviewObservation} from './entry-review-evidence';

export interface ControllerReviewGrounds {
  sourceDigest:string;
  language:string;
  verifiedLocalEntryInjection:boolean;
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
  entry:EntryReviewObservation|null|undefined):ControllerReviewGrounds {
  const proof=entryReplayFacts(entry);
  const verified=!!proof;
  const escaped=evidence.links.filter(link=>escapingOperation.test(link.code))
    .map(link=>lineRef(link.file,link.line));
  const plain=evidence.links.filter(link=>explicitlyPlainText.test(link.code))
    .map(link=>lineRef(link.file,link.line));
  const immutableFacts=[
    'Source-backed evidence digest '+evidence.sourceDigest+' ('+evidence.language+')',
    ...evidence.links.map(link=>lineRef(link.file,link.line)+': '+link.code.trim()).slice(0,70),
    ...(verified?['Independent sandbox entry replay preserved the exact attacker-chosen HTML markup in the handler output.']:[])
  ];
  return {
    sourceDigest:evidence.sourceDigest,language:evidence.language,
    verifiedLocalEntryInjection:verified,immutableFacts,
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
  if(decision.verdict!=='reject'||!grounds.verifiedLocalEntryInjection)return null;
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
