/** Validate observations, never the hidden fixture answer key. */
export interface ReasoningProbe {
  path: string;
  fn: string;
  kind: string;
  status: string;
  observed: boolean;
}
export function completedMarkup(probes: ReasoningProbe[], path: string): ReasoningProbe[] {
  return probes.filter(p => p.path === path && p.kind === 'html_reflection' &&
    ((p.status === 'behavior_observed' && p.observed === true) ||
     (p.status === 'behavior_not_observed' && p.observed === false)));
}
/** Flat lines avoid requiring escaped JSON nested inside an action's answer. */
export function parseReasoningAnswer(text: string): {files: any[]} {
  if(text.trim().startsWith('{') || text.trim()==='null')return JSON.parse(text);
  return {files:text.trim().split('\n').map(line=>{
    const match=line.trim().match(/^([^|]+)\s*\|\s*(true|false)\s*\|\s*(.+)$/);
    if(!match)throw new Error('Invalid classification line');
    return {path:match[1].trim(),rawMarkup:match[2]==='true',reason:match[3].trim()};
  })};
}
export function reasoningProgress(paths:string[], reads:Set<string>, probes:ReasoningProbe[]):string {
  const pending=paths.filter(path=>!completedMarkup(probes,path).length);
  return JSON.stringify({modules:paths.map(path=>({path,read:reads.has(path),observations:completedMarkup(probes,path).map(p=>({function:p.fn,rawMarkupObserved:p.observed}))})),
    pendingTests:pending,next:pending.length?'Inspect and test an untested module. Choose its formatting function from source; do not repeat completed tests.':'Both modules have observations. Return one line per module: path | true or false | evidence-based reason. Correct an irrelevant test by choosing a different function.'});
}
export function validateReasoningEvidence(text: string, paths: string[], probes: ReasoningProbe[]): string | null {
  // Prioritize all missing evidence before answer formatting or contradictions.
  const pending=paths.filter(path=>!completedMarkup(probes,path).length);
  if(pending.length)return `Final answer deferred: no completed markup observation exists for ${pending.join(', ')}. Choose relevant formatting functions from source and use verify_source. Failed, blocked, or unrelated tests do not establish the result. Do not repeat tests already completed for other modules.`;
  let value: any;
  try { value = parseReasoningAnswer(text); } catch { return 'Return one line per Python module in answer: filename.py | true or false | evidence-based reason. No nested JSON is needed.'; }
  if (!value || !Array.isArray(value.files)) return 'Return the requested files array or one classification line per module.';
  if (value.files.length !== paths.length || paths.some(path => value.files.filter((f: any) => f?.path === path).length !== 1))
    return 'Return exactly one classification for each Python module in the workspace, without duplicates or extra files.';
  for (const path of paths) {
    const answer = value.files.find((f: any) => f.path === path);
    if (typeof answer.rawMarkup !== 'boolean' || typeof answer.reason !== 'string' || !answer.reason.trim())
      return 'Each classification needs a rawMarkup boolean and an evidence-based reason.';
    const latest = completedMarkup(probes,path).at(-1)!;
    if (answer.rawMarkup !== latest.observed)
      return `Final answer deferred: the classification for ${path} contradicts the recorded observation for ${latest.fn}. Reconcile your conclusion with the returned test result and source. If you tested the wrong function, select and test the relevant one. Do not treat the fixed HTML wrapper as evidence that untrusted input survives unescaped.`;
  }
  return null;
}
