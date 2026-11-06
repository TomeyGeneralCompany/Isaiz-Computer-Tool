/** Source-grounded controller plan, shared by Java/Python/JavaScript.
 * Qwen never invents a selector, a sequence or its arguments; normal workflow
 * validation and sandbox execution are still required. Not vulnerability proof.
 */
import {guidedSourceProbe} from './source-guided-probes';
import {sourceStatefulPlans} from './controller-stateful-candidates';
import {controllerJavaProbes} from './controller-java-probe-inputs';

export type ControllerPolyglotPlan={
  action:'plan_probe';path:string;query:string;
  answer:'html_reflection'|'python_sequence'|'javascript_sequence'|'java_sequence';
  hypothesis:string;sequence?:unknown;
};

export function controllerPolyglotPlan(path:string,source:string,
  requested?:{query?:string;answer?:string}):ControllerPolyglotPlan|null {
  if(source.length>256000 || !/\.(?:py|java|js|mjs|cjs)$/.test(path))return null;
  const guided=guidedSourceProbe(path,source);
  const stateful=sourceStatefulPlans(path,source);
  // Java uses the same declaration-to-fixture planning policy as Solidity:
  // constructor and method argument values are controller-owned, not Qwen's.
  const javaPlans=controllerJavaProbes(path,source);
  const toPlan=(plan:(typeof javaPlans)[number]):ControllerPolyglotPlan=>({
    action:'plan_probe',path,query:plan.selector,answer:'java_sequence',
    hypothesis:'Observe the source-declared Java method with controller-generated safe arguments and a same-instance read/transition sequence; never presume a security impact.',
    sequence:plan.sequence
  });
  if(requested?.answer==='java_sequence') {
    const selectedJava=javaPlans.find(plan=>plan.selector===requested.query);
    return selectedJava?toPlan(selectedJava):null;
  }

  // Honor a source-grounded selected method when the model mangled its
  // declarative sequence; never silently change it to an unrelated method.
  const selected=stateful.find(p=>p.selector===requested?.query);
  if(selected && (!requested?.answer || requested.answer===selected.kind))
    return {action:'plan_probe',path,query:selected.selector,answer:selected.kind,
      hypothesis:'Observe bounded same-instance state transitions against the declared factory and method; observations are not security findings.',
      sequence:selected.sequence};
  if(guided && (!requested?.query || requested.query===guided.functionName) &&
     (!requested?.answer || requested.answer===guided.kind))
    return {action:'plan_probe',path,query:guided.functionName,answer:guided.kind,
      hypothesis:guided.hypothesis};
  if(requested?.query)return null;
  // Source-first discovery when the model has not selected an exact symbol.
  // Prefer the security-relevant HTML candidate before generic state effects.
  if(guided)return {action:'plan_probe',path,query:guided.functionName,
    answer:guided.kind,hypothesis:guided.hypothesis};
  if(javaPlans.length)return toPlan(javaPlans[0]);
  const first=stateful[0];
  return first ? {action:'plan_probe',path,query:first.selector,answer:first.kind,
    hypothesis:'Observe bounded source-declared state changes and independently verify their security relevance.',
    sequence:first.sequence} : null;
}


/** Resolve Qwen's intent against actual source declarations, regardless of the
 * model-selected probe kind. Never substitute an unrelated declared function.
 * Only correct a unique, source-backed method and the corresponding sequence.
 */
export function canonicalControllerPolyglotIntent(path:string,source:string,
  requested:{query:string;answer:string}):ControllerPolyglotPlan|null {
  if(!requested.query.trim())return controllerPolyglotPlan(path,source);
  const choices:ControllerPolyglotPlan[]=[];
  const direct=guidedSourceProbe(path,source);
  if(direct)choices.push({action:'plan_probe',path,query:direct.functionName,
    answer:direct.kind,hypothesis:direct.hypothesis});
  for(const p of sourceStatefulPlans(path,source))
    choices.push({action:'plan_probe',path,query:p.selector,answer:p.kind,
      hypothesis:'Controller source-declared same-instance state observation; an observation is not security proof.',
      sequence:p.sequence});
  for(const p of controllerJavaProbes(path,source))
    choices.push({action:'plan_probe',path,query:p.selector,answer:'java_sequence',
      hypothesis:'Controller-owned Java source-derived typed-argument sequence; independently verify the observed effect.',
      sequence:p.sequence});
  const matches=choices.filter(p=>p.query===requested.query ||
    (path.endsWith('.java') && p.query.split('.').at(-1)===requested.query));
  if(new Set(matches.map(p=>p.query)).size!==1)return null;
  // Same exact symbol can have both text and stateful adapters. An actual
  // literal HTML sink gets the context-aware HTML probe, not a generic state
  // sequence with weaker observations.
  return matches.find(p=>p.answer==='html_reflection')||matches[0]||null;
}
