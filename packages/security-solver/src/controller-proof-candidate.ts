/**
 * Controller-authored provisional findings from real source-linked reproduction.
 * This is NOT an approval: separate review still evaluates mitigations and impact.
 */
export type EntryProofCase={
  kind:string;behaviorObserved:boolean;
  observations?:unknown;
};
export type ControllerProofCandidate={
  caseId:string;severity:'low';confidence:number;ratingReason:string;
  title:string;impact:string;callerFile:string;callerLine:number;
  reachability:'caller';falsification:string;
};
export function controllerProofCandidate(args:{
  caseId:string;rendererFile:string;rendererSelector:string;
  callerFile:string;callerLine:number;callerSource:string;
  entryCase:EntryProofCase|null|undefined;
}):ControllerProofCandidate|null {
  const {caseId,rendererFile,rendererSelector,callerFile,callerLine,callerSource,entryCase}=args;
  if(!/^[a-f0-9]{64}$/.test(caseId) || !callerFile || !rendererFile ||
     !Number.isInteger(callerLine) || callerLine<1 || !entryCase ||
     entryCase.kind!=='entry_html_reflection' || !entryCase.behaviorObserved)return null;
  const value=entryCase.observations;
  if(!value || typeof value!=='object' || Array.isArray(value))return null;
  const o=value as Record<string,unknown>;
  const {control_input:controlInput,control_output:controlOutput,
    attack_input:attackInput,attack_output:attackOutput}=o;
  if(typeof controlInput!=='string'||!controlInput ||
     typeof controlOutput!=='string'||!controlOutput.includes(controlInput) ||
     typeof attackInput!=='string'||!attackInput ||
     typeof attackOutput!=='string'||!attackOutput.includes(attackInput) ||
     controlOutput===attackOutput ||
     !attackInput.includes('<')||!attackInput.includes('>'))return null;
  // An unrelated same-named method is not a caller. The upper layer verifies
  // the source import graph and the exact workspace-relative call position.
  const sourceLine=callerSource.split('\n')[callerLine-1]||'';
  const selector=rendererSelector.split('.').at(-1)||'';
  const invoked=new RegExp('(?:\\b|\\.)'+selector.replace(/[.*+?^$()|[\]\\{}]/g,'\\$&')+'\\s*\\(');
  if(!invoked.test(sourceLine) || /^\s*(?:\/\/|#|\*|\/\*)/.test(sourceLine))return null;
  return {
    caseId,severity:'low',confidence:0.55,
    ratingReason:'The controller reproduced local, source-linked entry-to-output HTML injection using attacker-chosen input and a contrasting control. The deployed route, content type, effective mitigations, scope and exploit impact remain questions for independent review.',
    title:'Controller-reproduced unescaped entry-to-output HTML reflection',
    impact:'Attacker-chosen markup was observed in the selected entry handler output; security impact depends on delivery and interpretation of that output.',
    callerFile,callerLine,reachability:'caller',
    falsification:'Independently replay the entry handler with control and injected values; check registration and reachability, HTML response context, content type, output encoding/sanitization and authorization. Reject if any security-critical premise is not established.'
  };
}
