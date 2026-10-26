/** Validate measured behavior and public task requirements, never the hidden answer key. */
export interface ReasoningProbe {
  path:string; fn:string; kind:string; status:string; observed:boolean;
  relevant:boolean;
}
export function matchesFormattingRequirement(observations:any):boolean {
  // README's public contract: preserve ordinary text inside one paragraph.
  // No expected function name or unsafe/safe classification is consulted.
  return typeof observations?.control_input==='string' &&
    observations.control_output===`<p>${observations.control_input}</p>`;
}
export function completedMarkup(probes:ReasoningProbe[],path:string):ReasoningProbe[] {
  return probes.filter(p=>p.path===path && p.kind==='html_reflection' && p.relevant &&
    ((p.status==='behavior_observed' && p.observed===true) ||
     (p.status==='behavior_not_observed' && p.observed===false)));
}
export function parseReasoningAnswer(text:string):{files:Array<{path:string;function:string;rawMarkup:boolean;reason:string}>} {
  return {files:text.trim().split('\n').map(line=>{
    const match=line.trim().match(/^([^|]+)\s*\|\s*([A-Za-z_][A-Za-z0-9_]*)\s*\|\s*(markup_survives|markup_escaped)$/);
    if(!match)throw new Error('Invalid classification line');
    const rawMarkup=match[3]==='markup_survives';
    return {path:match[1].trim(),function:match[2],rawMarkup,
      reason:rawMarkup?'The recorded probe preserved the supplied markup as an HTML element.':'The recorded probe did not preserve the supplied markup as an HTML element.'};
  })};
}
export function reasoningProgress(paths:string[],reads:Set<string>,probes:ReasoningProbe[]):string {
  const pending=paths.filter(path=>!completedMarkup(probes,path).length);
  return JSON.stringify({modules:paths.map(path=>({path,read:reads.has(path),
    observations:completedMarkup(probes,path).map(p=>({function:p.fn,rawMarkupObserved:p.observed})),
    unrelatedFunctions:[...new Set(probes.filter(p=>p.path===path&&!p.relevant).map(p=>p.fn))]})),
    pendingTests:pending,next:pending.length?'Inspect and test the paragraph-formatting function of a pending module. Utility tests do not cover that function. Select the function from source.':'Return one line per module: filename.py | tested_function | markup_survives OR markup_escaped. Use the observed result of that function.'});
}
export function validateReasoningEvidence(text:string,paths:string[],probes:ReasoningProbe[]):string|null {
  const pending=paths.filter(path=>!completedMarkup(probes,path).length);
  if(pending.length)return `Final answer deferred: no completed markup observation of the paragraph-formatting function exists for ${pending.join(', ')}. A completed utility test does not cover that requirement. Select the relevant function from source and use verify_source; do not repeat completed tests of other functions.`;
  let value:ReturnType<typeof parseReasoningAnswer>;
  try{value=parseReasoningAnswer(text);}catch{return 'Return one line per Python module: filename.py | tested_function | markup_survives OR markup_escaped. No boolean, explanation, or nested JSON is needed.';}
  if(value.files.length!==paths.length || paths.some(path=>value.files.filter(f=>f.path===path).length!==1))return 'Return exactly one classification per Python module without duplicates or extra files.';
  for(const answer of value.files) {
    const observation=completedMarkup(probes,answer.path).filter(p=>p.fn===answer.function).at(-1);
    if(!observation)return `No completed relevant observation supports ${answer.path}:${answer.function}. Report the paragraph-formatting function you actually tested, or test it first.`;
    if(answer.rawMarkup!==observation.observed)return `Final answer deferred: the classification for ${answer.path}:${answer.function} contradicts the recorded observation. Use markup_survives when the probe observed the supplied markup as an element, otherwise markup_escaped for this fixture. A fixed paragraph wrapper is not the supplied markup.`;
  }
  return null;
}
