/**
 * Controller-owned scenario ledger. The model may suggest hypotheses, but no
 * model response can invent precondition fulfillment or advance an experiment.
 * Every transition requires an explicit, recorded controller decision.
 */
export type ScenarioPhase =
  | 'discovered' | 'grounded' | 'preparing' | 'ready'
  | 'executing' | 'observed' | 'reviewing' | 'resolved';
export type ScenarioOutcome =
  | 'verified' | 'rejected' | 'unsupported' | 'incomplete';
export type PrerequisiteState = 'required' | 'satisfied' | 'blocked';
export interface ScenarioPrerequisite {
  id:string; description:string; dependsOn:string[];
  state:PrerequisiteState; evidence?:string; reason?:string;
}
export interface ScenarioEvidence {
  id:string; kind:'source'|'setup'|'execution'|'review';
  reference:string; observation:string;
}
export interface SecurityScenario {
  id:string; path:string; selector:string; language:'solidity'|'java'|'python'|'javascript';
  property:string; suspectedViolation:string; falsification:string;
  phase:ScenarioPhase; prerequisites:ScenarioPrerequisite[];
  evidence:ScenarioEvidence[]; attempts:number;
  outcome?:ScenarioOutcome; reason?:string;
}
const transitions:Record<ScenarioPhase,readonly ScenarioPhase[]>={
  discovered:['grounded','resolved'],
  grounded:['preparing','ready','resolved'],
  preparing:['preparing','ready','resolved'],
  ready:['executing','preparing','resolved'],
  executing:['observed','preparing','resolved'],
  observed:['reviewing','preparing','resolved'],
  reviewing:['resolved','preparing'],
  resolved:[]
};
const validId=(id:string)=>/^[a-zA-Z0-9_.:/-]{1,240}$/.test(id);
const clone=<T>(value:T):T=>JSON.parse(JSON.stringify(value)) as T;
export class ControllerScenarioLedger {
  private scenarios=new Map<string,SecurityScenario>();
  private history:Array<{id:string;from:ScenarioPhase;to:ScenarioPhase;reason:string}>=[];
  register(input:Pick<SecurityScenario,'id'|'path'|'selector'|'language'|
    'property'|'suspectedViolation'|'falsification'>):SecurityScenario {
    if(!validId(input.id)||!input.path||!input.selector)throw new Error('Invalid scenario identity');
    if(!input.property.trim()||!input.suspectedViolation.trim()||!input.falsification.trim())
      throw new Error('Security scenario requires property, violation and falsifier');
    const prior=this.scenarios.get(input.id);
    if(prior) {
      if(prior.path!==input.path||prior.selector!==input.selector||
         prior.property!==input.property||prior.suspectedViolation!==input.suspectedViolation||
         prior.falsification!==input.falsification)
        throw new Error('Conflicting scenario identity');
      return clone(prior);
    }
    const result:SecurityScenario={...input,phase:'discovered',prerequisites:[],
      evidence:[],attempts:0};
    this.scenarios.set(result.id,result);
    return clone(result);
  }
  get(id:string):SecurityScenario|undefined {
    const value=this.scenarios.get(id);return value?clone(value):undefined;
  }
  all():SecurityScenario[]{return [...this.scenarios.values()].map(clone);}
  private require(id:string):SecurityScenario {
    const value=this.scenarios.get(id);
    if(!value)throw new Error('Unknown controller scenario: '+id);
    return value;
  }
  transition(id:string,to:ScenarioPhase,reason:string):void {
    const scenario=this.require(id);
    if(!reason.trim()||!transitions[scenario.phase].includes(to))
      throw new Error('Invalid controller scenario transition '+scenario.phase+' -> '+to);
    if(to==='grounded'&&!scenario.evidence.some(item=>item.kind==='source'))
      throw new Error('Grounding requires recorded source evidence');
    if(to==='ready' && scenario.prerequisites.some(item=>item.state!=='satisfied'))
      throw new Error('Cannot execute with unresolved prerequisites');
    if(to==='observed'&&!scenario.evidence.some(item=>item.kind==='execution'))
      throw new Error('Observation requires actual execution evidence');
    if(to==='reviewing'&&!scenario.evidence.some(item=>item.kind==='execution'))
      throw new Error('Review requires actual execution evidence');
    const from=scenario.phase;
    scenario.phase=to;
    if(to==='executing')scenario.attempts++;
    this.history.push({id,from,to,reason:reason.slice(0,500)});
    if(this.history.length>1000)this.history.shift();
  }
  addPrerequisite(id:string,item:Omit<ScenarioPrerequisite,'state'|'evidence'|'reason'>):void {
    const scenario=this.require(id);
    if(scenario.phase==='resolved'||scenario.phase==='executing')
      throw new Error('Cannot change prerequisites during execution or after resolution');
    if(!validId(item.id)||scenario.prerequisites.some(value=>value.id===item.id))
      throw new Error('Duplicate or invalid prerequisite');
    if(item.dependsOn.includes(item.id))throw new Error('Self-dependent prerequisite');
    scenario.prerequisites.push({...item,dependsOn:[...new Set(item.dependsOn)],state:'required'});
    this.assertDependencies(scenario);
  }
  private assertDependencies(scenario:SecurityScenario):void {
    const byId=new Map(scenario.prerequisites.map(p=>[p.id,p]));
    const visited=new Set<string>(),active=new Set<string>();
    const walk=(id:string):void=>{
      if(active.has(id))throw new Error('Prerequisite cycle');
      if(visited.has(id))return;
      const item=byId.get(id);
      if(!item)throw new Error('Unknown prerequisite '+id);
      active.add(id);
      for(const dep of item.dependsOn)walk(dep);
      active.delete(id);visited.add(id);
    };
    for(const key of byId.keys())walk(key);
  }
  nextPrerequisite(id:string):ScenarioPrerequisite|undefined {
    const scenario=this.require(id);
    const byId=new Map(scenario.prerequisites.map(p=>[p.id,p]));
    const next=scenario.prerequisites.find(p=>p.state==='required' &&
      p.dependsOn.every(dep=>byId.get(dep)?.state==='satisfied'));
    return next?clone(next):undefined;
  }
  satisfy(id:string,key:string,evidence:string):void {
    const scenario=this.require(id),item=scenario.prerequisites.find(p=>p.id===key);
    if(!item||item.state!=='required'||!evidence.trim())
      throw new Error('Prerequisite not ready for satisfaction');
    if(!item.dependsOn.every(dep=>scenario.prerequisites.find(p=>p.id===dep)?.state==='satisfied'))
      throw new Error('Prerequisite dependencies unresolved');
    item.state='satisfied';item.evidence=evidence;
    this.record(id,{id:'setup:'+key,kind:'setup',reference:evidence,
      observation:'Controller verified prerequisite '+key});
  }
  block(id:string,key:string,reason:string):void {
    const scenario=this.require(id),item=scenario.prerequisites.find(p=>p.id===key);
    if(!item||item.state!=='required'||!reason.trim())throw new Error('Invalid blocked prerequisite');
    item.state='blocked';item.reason=reason;
  }
  record(id:string,evidence:ScenarioEvidence):void {
    const scenario=this.require(id);
    if(!evidence.id||!evidence.reference.trim()||!evidence.observation.trim())
      throw new Error('Evidence requires provenance and observation');
    const prior=scenario.evidence.find(e=>e.id===evidence.id);
    if(prior) {
      if(JSON.stringify(prior)!==JSON.stringify(evidence))throw new Error('Immutable evidence conflict');
      return;
    }
    scenario.evidence.push(clone(evidence));
  }
  finish(id:string,outcome:ScenarioOutcome,reason:string):void {
    const scenario=this.require(id);
    if(!reason.trim())throw new Error('Resolution reason required');
    if(outcome==='verified' && (scenario.phase!=='reviewing' ||
      !scenario.evidence.some(e=>e.kind==='review') ||
      !scenario.evidence.some(e=>e.kind==='execution') ||
      !scenario.evidence.some(e=>e.kind==='source')))
      throw new Error('Verified finding requires source, experiment and independent review');
    this.transition(id,'resolved',reason);
    scenario.outcome=outcome;scenario.reason=reason.slice(0,1000);
  }
  unresolved():SecurityScenario[]{return this.all().filter(s=>s.phase!=='resolved');}
  snapshot():{version:1;scenarios:SecurityScenario[];history:typeof this.history}{
    return clone({version:1 as const,scenarios:this.all(),history:this.history});
  }
  restore(data:unknown):void {
    const snapshot=data as ReturnType<ControllerScenarioLedger['snapshot']>;
    if(snapshot?.version!==1||!Array.isArray(snapshot.scenarios)||!Array.isArray(snapshot.history))
      throw new Error('Invalid scenario checkpoint');
    const restored=new ControllerScenarioLedger();
    for(const item of snapshot.scenarios){
      restored.register(item);
      const value=restored.require(item.id);
      value.prerequisites=clone(item.prerequisites);
      restored.assertDependencies(value);
      value.evidence=clone(item.evidence);
      value.phase=item.phase;value.attempts=item.attempts;
      value.outcome=item.outcome;value.reason=item.reason;
      if(!Object.hasOwn(transitions,item.phase))throw new Error('Invalid checkpoint phase');
      if(item.phase==='resolved'&&!item.outcome)throw new Error('Resolved scenario missing disposition');
    }
    this.scenarios=restored.scenarios;
    this.history=clone(snapshot.history).slice(-1000);
  }
}
