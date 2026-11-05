/** Source/probe-grounded report language shared by all four reproduction engines.
 * Qwen may propose hypotheses and provisional ratings, but must never author
 * the factual summary, observed impact, or falsification checks sent to review.
 * An independent reviewer still decides whether these observations are a bug.
 */
export type ReportNarrativeKind='html_reflection'|'path_construction'|'solidity_sequence'|string;
export function controllerReportNarrative(input:{
  kind:ReportNarrativeKind;selector:string;file:string;caseId:string;
  callerFile:string;callerLine:number;behaviorObserved:boolean
}):{title:string;summary:string;impact:string;falsification:string} {
  if(!input.behaviorObserved || !/^[a-f0-9]{64}$/.test(input.caseId) ||
     !input.file || !input.selector || !input.callerFile ||
     !Number.isSafeInteger(input.callerLine) || input.callerLine<1)
    throw new Error('Controller cannot construct a finding without recorded reproduction and caller');
  const target=input.selector+' in '+input.file;
  const evidence='Recorded case '+input.caseId+' observed behavior for '+target+
    '; source-referenced caller '+input.callerFile+':'+input.callerLine+'.';
  switch(input.kind) {
    case 'html_reflection':
      return {
        title:'Observed HTML reflection in '+input.selector,
        summary:evidence+' Isolated reflection is evidence of output behavior, not by itself proof of script execution.',
        impact:'Evaluate whether caller-controlled content reaches an HTML-rendering sink without effective context-sensitive escaping. Any browser execution or downstream exposure requires independent source-backed verification.',
        falsification:'Inspect the actual source-to-output chain for contextual HTML escaping, sanitization, input trust restrictions and rendering context; reproduce an escaped or otherwise blocked case to disprove a vulnerable reflection. Do not infer mitigation from a helper name.'
      };
    case 'solidity_sequence':
      return {
        title:'Observed state-changing transaction in '+input.selector,
        summary:evidence+' The controller has a recorded declarative on-chain transaction and state observation; the reviewer must independently assess access control and intended invariants.',
        impact:'Evaluate whether the recorded sender can perform a privileged state mutation and whether downstream contracts depend on that state. Actual unauthorized effects must follow from the recorded transaction and source, not model assertion.',
        falsification:'Check sender authorization and source-declared role guards against the recorded transaction account, then compare before/after state. A nonzero destination check alone does not authenticate the caller or disprove an unauthorized role change.'
      };
    case 'path_construction':
      return {
        title:'Observed path construction in '+input.selector,
        summary:evidence+' Isolated path behavior does not establish filesystem access.',
        impact:'Evaluate whether untrusted input can reach a privileged filesystem operation through the recorded caller and constructed path.',
        falsification:'Inspect canonicalization, containment checks, allowed roots and actual downstream filesystem use; a constructed path without reachable file access is not itself a traversal finding.'
      };
    default:
      return {
        title:'Observed source behavior in '+input.selector,
        summary:evidence,
        impact:'Assess security significance from the recorded observations, source caller, and actual application behavior; a completed local probe is not automatically a vulnerability.',
        falsification:'Inspect actual mitigations, attacker influence, applicable scope, and the reachable effects in the recorded source chain.'
      };
  }
}
