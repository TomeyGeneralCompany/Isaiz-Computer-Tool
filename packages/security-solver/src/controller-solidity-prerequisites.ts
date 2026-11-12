/**
 * Offline preparation-graph validation. This module NEVER reads source files,
 * calls a model, invokes a verifier or schedules a controller action.
 */
export type PrerequisiteKind =
  | 'compile'|'link'|'deploy'|'initialize'|'grant_role'
  | 'fund'|'approve'|'set_state'|'assert_state';
export type PrerequisiteBlocker =
  | 'DUPLICATE_PREREQUISITE'
  | 'UNKNOWN_PREREQUISITE'
  | 'CYCLIC_DEPENDENCY'
  | 'INVALID_PREREQUISITE'
  | 'UNPROVEN_PREREQUISITE';
export interface SourceWitness {
  path:string; sourceSha256:string; start:number; end:number; symbol:string;
}
export interface PreparationPrerequisite {
  id:string;
  kind:PrerequisiteKind;
  dependsOn:string[];
  sourceEvidence:SourceWitness[];
  parameters:Record<string,unknown>;
}
export type PreparationResult =
  | {ok:true; ordered:PreparationPrerequisite[]}
  | {ok:false; code:PrerequisiteBlocker; detail:string};

const validId=/^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/;
const validHash=/^[a-f0-9]{64}$/;
export function validateSourceWitness(e:SourceWitness):boolean {
  return !!e && typeof e.path==='string' && !e.path.startsWith('/') &&
    !e.path.split('/').includes('..') && e.path.length>0 &&
    validHash.test(e.sourceSha256) && Number.isSafeInteger(e.start) &&
    Number.isSafeInteger(e.end) && e.start>=0 && e.end>e.start &&
    typeof e.symbol==='string' && e.symbol.length>0;
}
export function orderPreparation(
  steps:readonly PreparationPrerequisite[]
):PreparationResult {
  const nodes=new Map<string,PreparationPrerequisite>();
  for(const step of steps) {
    if(!step || typeof step.id!=='string' || !validId.test(step.id) ||
      !Array.isArray(step.dependsOn) || !Array.isArray(step.sourceEvidence) ||
      !step.parameters || typeof step.parameters!=='object' ||
      Array.isArray(step.parameters) ||
      !step.sourceEvidence.every(validateSourceWitness)) {
      return {ok:false,code:'INVALID_PREREQUISITE',detail:'Invalid prerequisite identity or witness'};
    }
    if(!step.sourceEvidence.length)
      return {ok:false,code:'UNPROVEN_PREREQUISITE',detail:step.id};
    if(nodes.has(step.id))
      return {ok:false,code:'DUPLICATE_PREREQUISITE',detail:step.id};
    nodes.set(step.id,step);
  }
  for(const step of steps) for(const dependency of step.dependsOn)
    if(!nodes.has(dependency))
      return {ok:false,code:'UNKNOWN_PREREQUISITE',
        detail:step.id+' depends on '+dependency};
  const visiting=new Set<string>(),visited=new Set<string>();
  const ordered:PreparationPrerequisite[]=[];
  const visit=(id:string):string|null=>{
    if(visiting.has(id))return id;
    if(visited.has(id))return null;
    visiting.add(id);
    const step=nodes.get(id)!;
    for(const dependency of [...new Set(step.dependsOn)].sort()) {
      const cycle=visit(dependency);if(cycle)return cycle;
    }
    visiting.delete(id);visited.add(id);ordered.push(step);
    return null;
  };
  for(const id of [...nodes.keys()].sort()) {
    const cycle=visit(id);
    if(cycle)return {ok:false,code:'CYCLIC_DEPENDENCY',detail:cycle};
  }
  return {ok:true,ordered};
}
