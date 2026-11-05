/** Source-grounded controller plan, shared by Java/Python/JavaScript.
 * Qwen never invents a selector, a sequence or its arguments; normal workflow
 * validation and sandbox execution are still required. Not vulnerability proof.
 */
import {guidedSourceProbe} from './source-guided-probes';
import {sourceStatefulPlans} from './controller-stateful-candidates';

export type ControllerPolyglotPlan={
  action:'plan_probe';path:string;query:string;
  answer:'html_reflection'|'python_sequence'|'javascript_sequence';
  hypothesis:string;sequence?:unknown;
};

export function controllerPolyglotPlan(path:string,source:string,
  requested?:{query?:string;answer?:string}):ControllerPolyglotPlan|null {
  if(source.length>256000 || !/\.(?:py|java|js|mjs|cjs)$/.test(path))return null;
  const guided=guidedSourceProbe(path,source);
  const stateful=sourceStatefulPlans(path,source);
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
  const first=stateful[0];
  return first ? {action:'plan_probe',path,query:first.selector,answer:first.kind,
    hypothesis:'Observe bounded source-declared state changes and independently verify their security relevance.',
    sequence:first.sequence} : null;
}
