/**
 * Runtime-owned entry evidence is deliberately distinct from lexical caller
 * discovery and from a simulated browser attack. This reconciles only facts
 * actually observed by the isolated entry-point replay.
 */
export type EntryReviewObservation={
  status?:string;
  behavior_observed?:boolean;
  kind?:string;
  observations?:{
    control_input?:string;
    control_output?:string;
    attack_input?:string;
    attack_output?:string;
    entry_attack_url?:string;
    entry_control_url?:string;
    entry_parameter?:string;
    entry_selector?:string;
  };
};

export type EntryReviewDecision={
  verdict:string;
  issues?:Array<{severity?:string;description?:string}>;
  reasoning?:string;
};

export function entryReplayFacts(result:EntryReviewObservation|null|undefined):string|null {
  if(!result || !result.behavior_observed || result.kind!=='entry_html_reflection')return null;
  const o=result.observations;
  if(!o || !o.attack_input || !o.attack_output ||
     !o.attack_output.includes(o.attack_input))return null;
  const urlSource=o.entry_attack_url && o.entry_parameter
    ? 'The controller constructed an encoded attacker-chosen query-string value ('+
      o.entry_parameter+') and executed the selected source-declared entry function with that URL.'
    : 'The controller passed an attacker-chosen test string directly to the selected source-declared entry function.';
  return urlSource+
    ' The independent sandbox replay observed that the entry handler returned the exact unescaped attacker-supplied HTML element.'+
    ' This proves a local handler input-to-output injection path (not a deployed HTTP route, JavaScript execution, or browser rendering).';
}

/**
 * Error feedback, never automatic approval. Rejects only reviews whose
 * factual premise is contradicted by an independently replayed entry case.
 * Independent review may still reject for an actual context/privilege gap.
 */
export function entryReviewRejectionDefect(
  decision:EntryReviewDecision,
  entry:EntryReviewObservation|null|undefined
):string|null {
  if(decision.verdict!=='reject'||!entryReplayFacts(entry))return null;
  const prose=[
    decision.reasoning||'',
    ...(decision.issues||[]).filter(x=>x.severity==='fatal').map(x=>x.description||'')
  ].join(' ');
  const deniesControlledInput=/\b(?:no (?:attacker|external|user)[ -]?(?:controlled|control|influence)|cannot (?:control|influence)|does not (?:prove|show|demonstrate) (?:attacker|user) control|no (?:actual )?input.to.sink (?:path|edge)|input is not (?:attacker|user)[ -]controlled)\b/i.test(prose);
  if(deniesControlledInput)
    return 'Independent controller replay executed the source-declared entry function with attacker-chosen input and observed the exact input in its returned HTML. Do not deny local entry input control or the observed input-to-output path. You may reject if a separate production reachability, authorization, content type, or impact issue is actually missing; name that gap precisely.';
  const assertsEscaping=/\b(?:html[- ]?escap(?:ed|ing)|escaped in (?:the )?(?:html|output|response)|encoded as (?:plain )?text|safely escaped|not (?:interpreted|inserted) as markup|only (?:plain|literal) text)\b/i.test(prose);
  const falselyEquatesWrapping=/\b(?:wrapped|wrapping|inside|within|child|children|<p>|paragraph)\b/i.test(prose);
  if(assertsEscaping && (falselyEquatesWrapping||/html[- ]?escap(?:ed|ing)|safely escaped/.test(prose.toLowerCase())))
    return 'The entry replay returns the exact unescaped HTML element as markup; wrapping it in paragraph tags is not HTML escaping. The local source-to-output injection is observed. Do not infer JavaScript execution or deployed browser context; identify a real source-backed mitigation or other independent impact gap if rejecting.';
  // Lack of browser JavaScript execution is a valid limitation, but is not
  // evidence that HTML markup is inert. Ask for a narrower, sourced objection.
  const claimsInertness=/\b(?:not rendered in a context|not rendered as html|output is (?:inert|plain text)|browser (?:does not|cannot|never) (?:execute|render|interpret)|no security.relevant output|does not constitute a security vulnerability)\b/i.test(prose);
  if(claimsInertness && !/\b(?:content[- ]type|text\/plain|escaped|sandboxed|CSP|content security policy|not deployed|only local|untrusted input required|production route)\b/i.test(prose))
    return 'The controller observed unescaped attacker-chosen HTML as an entry-handler output. A local HTML-injection finding is not identical to demonstrated JavaScript execution, but absence of browser execution alone does not establish that the HTML output is inert. If rejecting, state the specific technical context or mitigation that prevents security relevance rather than denying the observed markup.';
  return null;
}
