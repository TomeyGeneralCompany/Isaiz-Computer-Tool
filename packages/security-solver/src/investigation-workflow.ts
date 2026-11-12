import { Annotation, StateGraph, START, END } from '@langchain/langgraph';
import { isDeepStrictEqual } from 'node:util';
import {createHash} from 'node:crypto';
import {ControllerStageLock} from './controller-stage-lock';
import {ControllerScenarioLedger} from './controller-scenario-lifecycle';
import type { decodeAuditAction } from './local-audit-protocol';
type Action = ReturnType<typeof decodeAuditAction>;
type Stage = 'inspect'|'hypothesize'|'test'|'review';
const State = Annotation.Root({
  stage: Annotation<Stage>(), inspections: Annotation<number>(),
  pending: Annotation<Action|null>(), tested: Annotation<string[]>(),
});
/** A bounded, sequential graph. It routes work; it never supplies a finding. */
const graph = new StateGraph(State)
  .addNode('route', state => ({stage: state.pending ? 'test' as const :
    state.inspections >= 6 ? 'hypothesize' as const : state.tested.length ? 'review' as const : 'inspect' as const}))
  .addEdge(START, 'route').addEdge('route', END).compile();
/** Reject only explicit contradictions between a hypothesis and its chosen probe.
 * Ambiguous hypotheses remain eligible for ordinary source/runtime validation. */
export function probeHypothesisMismatch(kind:string,hypothesis:string):string|null {
  const h=hypothesis.toLowerCase();
  const path= /\b(?:path traversal|directory traversal|directory escape|filesystem path traversal)\b/.test(h);
  const html= /\b(?:html reflection|html injection|cross.site scripting|\bxss\b|unescaped html|html escaping)\b/.test(h);
  if(path && !html && kind==='html_reflection')
    return 'Wrong probe: html_reflection measures HTML output. Correct probe for this path-traversal hypothesis: path_construction. Set answer="path_construction" and inspect whether the method constructs a filesystem path before planning. If it does not, this hypothesis is unsupported by the available probe; do not test an unrelated method.';
  if(html && !path && kind==='path_construction')
    return 'Wrong probe: path_construction measures filesystem path behavior. Correct probe for this HTML-output hypothesis: html_reflection. Set answer="html_reflection" and ensure the inspected method returns compatible text before planning. If it does not, this hypothesis is unsupported by the available probe.';
  return null;
}

const key = (a:Action) => JSON.stringify([a.path,a.query,a.answer,a.sequence]);
export class InvestigationWorkflow {
  private stageLock:ControllerStageLock|null=null;
  bindStageLock(lock:ControllerStageLock){
    if(this.stageLock)throw new Error('STAGE_LOCK_ALREADY_BOUND');
    this.stageLock=lock;
  }
  readonly scenarios=new ControllerScenarioLedger();
  private scenarioMap=new Map<string,string>();
  private sourceEvidence=new Map<string,string[]>();
  recordSourceEvidence(path:string,id:string){
    if(!this.readPaths.has(path)||!/^[a-f0-9]{64}$/.test(id))
      throw new Error('Cannot attach evidence to an unread source');
    const old=this.sourceEvidence.get(path)||[];
    if(!old.includes(id))this.sourceEvidence.set(path,[...old,id].slice(-64));
    this.recordEvidence(id);
  }
  latestSourceEvidence(path:string):string|undefined {
    return this.sourceEvidence.get(path)?.at(-1);
  }
  private scenarioKey(path:string,query:string,kind:string){
    return JSON.stringify([path,query,kind]);
  }
  registerControllerPlan(plan:{path:string;query:string;answer:string;hypothesis:string},
    sourceReference:string,property:string,falsifier:string) {
    if(!this.readPaths.has(plan.path))throw new Error('Source not inspected');
    if(!sourceReference || !property || !falsifier)throw new Error('Ungrounded controller scenario');
    const language=plan.path.endsWith('.sol')?'solidity':
      plan.path.endsWith('.java')?'java':plan.path.endsWith('.py')?'python':'javascript';
    const key=this.scenarioKey(plan.path,plan.query,plan.answer);
    const id=createHash('sha256').update(key).digest('hex');
    const record=this.scenarios.register({id,path:plan.path,selector:plan.query,
      language,property,suspectedViolation:plan.hypothesis,falsification:falsifier});
    this.scenarioMap.set(key,id);
    if(record.phase==='discovered'){
      this.scenarios.record(id,{id:'source:initial',kind:'source',
        reference:sourceReference,observation:'Inspected declaration '+plan.query});
      this.scenarios.transition(id,'grounded','Controller selected source-backed candidate');
      this.scenarios.transition(id,'preparing','Resolve verifier prerequisites');
      this.scenarios.addPrerequisite(id,{id:'source',description:'Inspected declaration',dependsOn:[]});
      this.scenarios.addPrerequisite(id,{id:'plan',description:'Validated executable plan',dependsOn:['source']});
      this.scenarios.addPrerequisite(id,{id:'runtime',description:'Verifier confirms isolated runtime, dependencies and setup',dependsOn:['plan']});
      this.scenarios.satisfy(id,'source',sourceReference);
    }
  }
  preparedControllerPlan(path:string,query:string,kind:string){
    const id=this.scenarioMap.get(this.scenarioKey(path,query,kind));
    if(!id||this.scenarios.get(id)?.phase!=='preparing')return;
    this.scenarios.satisfy(id,'plan','controller-validated:'+kind+':'+query);
    // The verifier must resolve runtime dependencies and setup first.
    // A syntactically valid sequence alone must never make this READY.
  }
  private observeScenario(action:Action,output:string){
    const id=this.scenarioMap.get(this.scenarioKey(action.path,action.query,action.answer));
    if(!id)return;
    const current=this.scenarios.get(id);
    if(current?.phase!=='preparing')return;
    let result:any;try{result=JSON.parse(output);}catch{result={status:'tool_error'};}
    const status=String(result?.status||'tool_error');
    const supported=new Set(['behavior_observed','behavior_not_observed','observation_only']);
    if(!supported.has(status) || !result?.observations) {
      // A failed install, unresolved import, unproven fixture or unavailable
      // sandbox is a failed prerequisite, NOT a completed experiment.
      const reason=String(result?.detail||result?.limitation||result?.error||status).slice(0,1000);
      this.scenarios.block(id,'runtime',reason);
      this.scenarios.record(id,{id:'setup:blocked',kind:'setup',
        reference:'runtime:'+status,observation:reason});
      this.scenarios.finish(id,
        ['unsupported_dependencies','unsupported_execution','invalid_probe',
          'blocked_no_runtime','blocked_no_sandbox'].includes(status)?'unsupported':'incomplete',
        'Isolated runtime prerequisite failed: '+reason);
      return;
    }
    const reference=String(result.caseId||result.evidenceFile||
      'runtime:'+action.path+':'+action.query+':'+status);
    this.scenarios.satisfy(id,'runtime',reference);
    this.scenarios.transition(id,'ready','Verifier confirmed dependency and fixture preparation');
    this.scenarios.transition(id,'executing','Execute source-grounded isolated experiment');
    const attempts=this.scenarios.get(id)!.attempts;
    this.scenarios.record(id,{id:'execution:'+attempts,kind:'execution',
      reference,observation:status});
    this.scenarios.transition(id,'observed','Verifier returned actual experiment observations');
    if(status==='behavior_observed')
      this.scenarios.transition(id,'reviewing','Independent reviewer must assess security relevance');
    else this.scenarios.finish(id,status==='behavior_not_observed'?'rejected':'incomplete',
      'Isolated experiment disposition: '+status);
  }
  acceptedReview(path:string,query:string,kind:string,reference:string,positive:boolean){
    const id=this.scenarioMap.get(this.scenarioKey(path,query,kind));
    if(!id||this.scenarios.get(id)?.phase!=='reviewing')return;
    this.scenarios.record(id,{id:'review:independent',kind:'review',reference,
      observation:positive?'Validated positive case':'Validated negative case'});
    this.scenarios.finish(id,positive?'verified':'rejected',
      'Independent final validator accepted case disposition');
  }
  private state:typeof State.State={stage:'inspect',inspections:0,pending:null,tested:[]};
  private readPaths=new Set<string>();
  private outlinedPaths=new Set<string>();
  private attemptedOutlines=new Set<string>();
  private latestSolidityPath:string|null=null;
  private requiredSource:string|null=null;
  private requiredSourceQueue:string[]=[];
  private verifiedEvidenceFocus:string|null=null;
  private recoveryProbe:{path:string;query:string;kind:string}|null=null;
  private requiredProbePlanning=false;
  private requiredProbeKind:string|null=null;
  private requiredProbePlanningRejections=0;
  private duplicateProbeRejections=0;
  private observations:Array<{path:string;function:string;kind:string;status:string;caseId?:string;evidenceFile?:string;behaviorObserved?:boolean}>=[];
  private lastFeedback='';
  private decisions:Array<{path:string;question:string;offset:number}>=[];
  private priorNotes:string[]=[];
  private evidenceReferences:string[]=[];
  recordEvidence(id:string) {
    if(!/^[a-f0-9]{64}$/.test(id))throw new Error('Invalid controller evidence reference');
    if(!this.evidenceReferences.includes(id))this.evidenceReferences.push(id);
    this.evidenceReferences=this.evidenceReferences.slice(-24);
  }

  private controllerCandidatesComplete=false;
  finishControllerCandidates() {
    if(this.state.pending || this.requiredSource)return false;
    this.controllerCandidatesComplete=true;
    this.feedback('All supported controller candidates and source pages were examined. Assess only the recorded evidence; explain unsupported execution or missing impact rather than inventing a finding.');
    return true;
  }

  private pageTurns=0;
  private continuations=new Map<string,number>();
  private readSpans=new Set<string>();
  private sourceProgress=0;
  private nextOffsets=new Map<string,number|null>();
  private progressAtDecision=0;
  restore(value:unknown) {
    // Prior state directs navigation only. Current-run reads and probes must revalidate it.
    const saved=value as any;
    if(saved?.version!==1 || !Array.isArray(saved.notes))return;
    // Checkpoint IDs belong to the previous run's archive. They cannot be
    // dereferenced in a fresh log or promoted to current-run evidence.
    this.evidenceReferences=[];
    this.priorNotes=saved.notes.filter((n:unknown)=>typeof n==='string').slice(-12).map((n:string)=>n.slice(0,400));
  }
  memory() {
    return {version:1,evidenceReferences:this.evidenceReferences,notes:[...this.priorNotes,
      ...this.decisions.slice(-6).map(d=>'Unresolved context: '+JSON.stringify(d)),
      ...(this.state.pending?['Candidate needing fresh evidence: '+JSON.stringify(this.state.pending)]:[]),
      ...this.observations.slice(-6).map(o=>'Prior observation; replay required: '+JSON.stringify(o))].slice(-12).map(n=>n.slice(0,400))};
  }
  continueInspection(action:Action) {
    const question=action.hypothesis!.trim();
    const id=JSON.stringify([action.path,action.offset||0,action.query]);
    this.progressAtDecision=this.sourceProgress;
    this.continuations.set(id,(this.continuations.get(id)||0)+1);
    this.decisions.push({path:action.path,question,offset:action.offset||0});
    this.decisions=this.decisions.slice(-32);
    this.state.inspections=0;this.pageTurns=0;this.lastFeedback='';
  }
  async constraints() {
    if(this.stageLock){
      const stage=this.stageLock.currentStage;
      if(stage==='READ')return {action:['read_file']};
      if(stage==='ANALYZE')return {action:['finalize_analysis']};
      if(stage==='EXPERIMENT'){
        if(this.state.pending){
          const p=this.state.pending;
          return {action:['verify_source'],path:[p.path],query:[p.query],answer:[p.answer]};
        }
        return {action:['plan_probe','probe_intent']};
      }
      if(stage==='REVIEW'||stage==='REPORT')return {action:['final']};
      throw new Error('STAGE_LOCKED: '+stage);
    }
    if(this.pageTurns>=8)this.state.inspections=Math.max(6,this.state.inspections);
    this.state=await graph.invoke(this.state);
    if(this.requiredSource)return {action:['read_file'],path:[this.requiredSource]};
    if(this.controllerCandidatesComplete && !this.state.pending)return {action:['final']};
    // Once the controller has source-grounded reachability evidence for an
    // observed reproduction, further exploration cannot displace this case.
    // Only a final technical assessment (including a supported rejection) is
    // permitted until the reviewer settles it.
    if(this.verifiedEvidenceFocus && !this.state.pending)return {action:['final']};
    // After a long paginated Solidity read, surface declarations before allowing
    // another speculative final. Once attempted, never trap an unparseable file.
    if(this.pageTurns>=6 && this.latestSolidityPath && !this.attemptedOutlines.has(this.latestSolidityPath) && !this.state.pending) {
      this.attemptedOutlines.add(this.latestSolidityPath);
      return {action:['outline_solidity'],path:[this.latestSolidityPath]};
    }
    if(this.recoveryProbe)return {action:['plan_probe'],path:[this.recoveryProbe.path],query:[this.recoveryProbe.query],answer:[this.recoveryProbe.kind]};
    if(this.requiredProbePlanning && !this.state.pending)return {action:['plan_probe'],...(this.requiredProbeKind?{answer:[this.requiredProbeKind]}:{})};
    if(this.duplicateProbeRejections>=2 && !this.state.pending)return {action:['read_file','read_solidity','outline_solidity','search_files','list_files','plan_probe','continue_inspection','final']};
    if(this.state.pending) {
      const p=this.state.pending;
      return {action:['verify_source'],path:[p.path],query:[p.query],answer:[p.answer]};
    }
    return {action:this.state.stage==='hypothesize' ?
      // Hypothesis stage must not hide inspection tools while selected sources
      // still have unread pages: real Solidity reviews can span many pages.
      (this.nextOffsets.size && [...this.nextOffsets.values()].some(offset=>offset!==null) ?
        ['read_file','read_solidity','outline_solidity','plan_probe','continue_inspection','final'] :
        // The controller may still have ranked unread files after all currently
        // tracked pages finish. Do not revoke source access at hypothesis stage.
        ['read_file','read_solidity','outline_solidity','plan_probe','continue_inspection','final']) :
      ['read_file','read_solidity','outline_solidity','search_files','list_files','plan_probe','final']};
  }
  note():string {
    const note={unansweredQuestion:this.decisions.length?{...this.decisions.at(-1)!,path:this.decisions.at(-1)!.path.slice(0,160),question:this.decisions.at(-1)!.question.slice(0,250)}:undefined,priorNavigation:this.priorNotes.slice(-1).map(n=>n.slice(0,200)),pageTurns:this.pageTurns,stage:this.stageLock?.currentStage||this.state.stage,inspectionsSinceDecision:this.state.inspections,
      recentReadPaths:[...this.readPaths].slice(-3).map(p=>p.slice(0,160)),nextUnreadPages:[...this.nextOffsets].filter(([,offset])=>offset!==null).slice(-3).map(([path,offset])=>({path:path.slice(0,160),offset})),pending:this.state.pending ? {path:this.state.pending.path.slice(0,160),function:this.state.pending.query,kind:this.state.pending.answer} : null,
      observations:this.observations.slice(-2).map(o=>({...o,path:o.path.slice(0,160)})),
      // Compact controller-owned case ledger survives Qwen context eviction.
      // These are recorded probe outcomes, never model claims or approvals.
      observationLedger:this.observations.slice(-8).map(o=>({path:o.path.slice(0,100),function:o.function.slice(0,72),status:o.status,caseId:o.caseId,behaviorObserved:o.behaviorObserved})),
      evidenceReferences:this.evidenceReferences.slice(-3),verifiedEvidenceFocus:this.verifiedEvidenceFocus,feedback:this.lastFeedback.slice(0,240),
      instruction:this.verifiedEvidenceFocus?'The controller has locked a source-reproduced case '+this.verifiedEvidenceFocus+'. Assess its technical security significance against the recorded observations, caller chain and mitigations. Do not select new navigation or probes; a supported negative judgment is valid.':this.state.pending?'Execute the planned probe with exactly its path, function, kind and sequence.':
        'Read relevant source, then plan_probe with path, query=function, answer=probe kind, hypothesis=claim AND disproof condition. After six inspections or eight source pages, choose plan_probe, continue_inspection with a specific unanswered question in hypothesis and the next path/offset/query, or an incomplete final. Continue only to obtain that missing evidence; no forced unrelated test. A failed or unsupported verification is not proof of absence or presence. After inspecting recorded evidence, change candidate or request specific missing context; do not repeat completed evidence pages. Read recorded evidenceFile pages when an observation leaves context instead of repeating its probe. After testing inspect caller/mitigations before reporting; observations alone are not findings.'};
    if(this.stageLock?.currentStage==='READ')
      note.instruction='READ stage locked: complete every indexed source page. Never plan, execute or review experiments before the controller verifies complete source coverage.';
    else if(this.stageLock?.currentStage==='EXPERIMENT')
      note.instruction=this.state.pending?'Execute only the exact queued controller-selected verifier request.':'Execute only the next controller-queued experiment. Do not select unqueued experiments or read new source pages.';
    else if(this.stageLock?.currentStage==='REVIEW')
      note.instruction='All queued experiments are terminal. Independently review recorded observation evidence; do not run new experiments.';
    else if(this.stageLock?.currentStage==='REPORT')
      note.instruction='Independent review completed. Produce only the validated evidence-based report.';
    // Evidence is controller-owned and must survive conversation compaction.
    // Discard navigation prose before dropping a verified reproduction record.
    while(JSON.stringify(note).length>1800 && note.priorNavigation.length)note.priorNavigation.shift();
    while(JSON.stringify(note).length>1800 && note.recentReadPaths.length)note.recentReadPaths.shift();
    while(JSON.stringify(note).length>1800 && note.nextUnreadPages.length)note.nextUnreadPages.shift();
    if(JSON.stringify(note).length>1800)note.instruction='Preserve recorded probe evidence. Inspect unresolved caller reachability and impact before reporting; do not repeat completed probes.';
    if(JSON.stringify(note).length>1800)note.feedback=note.feedback.slice(0,100);
    while(JSON.stringify(note).length>1800 && note.observations.length>1)note.observations.shift();
    while(JSON.stringify(note).length>1800 && note.observationLedger.length>1)note.observationLedger.shift();
    if(JSON.stringify(note).length>1800)note.unansweredQuestion=undefined;
    return JSON.stringify(note);
  }
  requireProbe(path:string,query:string,kind:string) {
    this.recoveryProbe={path,query,kind};
    this.feedback('Unverified proposed finding: plan this inspected declared function with a concrete disproof condition, then execute verify_source. If the probe is unsupported, continue with another candidate.');
  }
  clearProbeRecovery() {this.recoveryProbe=null;}
  requireProbePlanning(hints:string,kind?:string) {
    // The validator explicitly requires a test; constrain the action, not an
    // arbitrary function or probe kind. The model must select a relevant target.
    this.requiredProbePlanning=true;
    this.requiredProbeKind=kind||null;
    this.requiredProbePlanningRejections=0;
    this.feedback('Testing required before classification. Select a relevant declared function and a supported probe kind from inspected source. Declarations: '+hints.slice(0,260));
  }
  rejectedRequiredProbePlan():boolean {
    if(!this.requiredProbePlanning)return false;
    if(++this.requiredProbePlanningRejections<2)return false;
    // An invalid or invented plan must never trap the controller in a
    // plan_probe-only state. Resume ordinary inspection/final choices.
    this.requiredProbePlanning=false;
    this.requiredProbeKind=null;
    this.requiredProbePlanningRejections=0;
    this.feedback('Required probe planning failed twice. Inspect a different eligible function or explain the incomplete evidence; do not invent a probe.');
    return true;
  }
  rejectedDuplicateProbe() {this.duplicateProbeRejections++;this.feedback('The already attempted probe cannot be repeated. Return outcome=no_testable_candidate with a specific reason and findings=[]; do not claim an unverified vulnerability.');}
  requireSource(path:string) {
    // A page already inspected by the workflow is not an outstanding
    // requirement. Requiring it again creates a forced-read feedback loop:
    // the controller asks for the completed page, navigation redirects it,
    // and the outstanding requirement is never released.
    if(this.readPaths.has(path)){
      if(this.requiredSource===path)this.requiredSource=this.requiredSourceQueue.shift()||null;
      this.feedback('Source '+path+' is already inspected. Use the recorded evidence, trace a real caller, or plan a supported probe.');
      return;
    }
    this.requiredSource=path;this.feedback('Read '+path+' before planning its test.',true);
  }
  requireSources(paths:string[]) {
    const fresh=[...new Set(paths)].filter(path=>!this.readPaths.has(path));
    this.requiredSource=fresh.shift()||null;
    this.requiredSourceQueue=fresh;
    if(this.requiredSource)this.feedback('Controller-selected caller chain requires reading '+this.requiredSource+'.',true);
  }
  focusVerifiedEvidence(caseId:string) {
    if(!/^[a-f0-9]{64}$/.test(caseId))return false;
    if(!this.observations.some(o=>o.caseId===caseId && o.status==='behavior_observed'))return false;
    this.verifiedEvidenceFocus=caseId;
    this.requiredProbePlanning=false;this.requiredProbeKind=null;
    this.recoveryProbe=null;
    this.feedback('Verified behavior and source-backed caller recorded. Make a bounded technical assessment of this case; do not navigate unrelated sources or invent other probe actions. An assessed non-vulnerability remains a valid outcome.');
    return true;
  }
  /** Recover from repeated unsupported model plans using already ranked source.
   * This requires a genuine next read; it never fabricates a probe or evidence. */
  requireNextUnreadSource(prioritized:string[]):string|null {
    if(this.requiredSource)return null;
    const next=prioritized.find(path=>
      path.startsWith('source-') &&
      /\.(?:sol|java|py|js|mjs|cjs|ts|tsx|jsx)$/.test(path) &&
      !this.readPaths.has(path));
    if(!next)return null;
    this.requireSource(next);
    return next;
  }
  validate(action:Action):string|null {
    if(this.stageLock){
      const stage=this.stageLock.currentStage;
      if(stage==='REVIEW' && action.action==='final'){
        // A proposed final is input to independent review, not a report.
      }else{
        try{this.stageLock.assertActionAllowed(action.action);}
        catch(error){return String(error);}
      }
    }
    if(this.requiredSource && (action.action!=='read_file' || action.path!==this.requiredSource))return 'Read the required candidate source '+this.requiredSource+' before other actions.';
    if(action.action==='continue_inspection') {
      if(!action.hypothesis?.trim() || action.hypothesis.trim().length<20 || !action.path || action.path.length>512)
        return 'Name the next source path and explain the specific missing evidence in hypothesis (20–600 characters).';
      const id=JSON.stringify([action.path,action.offset||0,action.query]);
      if((this.continuations.get(id)||0)>=1)return 'This source continuation was already attempted at the same offset. Choose new evidence, a supported probe, or conclude incomplete.';
      if(this.decisions.length>0 && this.sourceProgress<=this.progressAtDecision)return 'No new source range was read since the last decision. Plan a supported probe or conclude incomplete; repeating inspection cannot provide new evidence.';
    }
    if(action.action==='plan_probe') {
      if(action.path.length>512)return 'Choose a workspace-relative source path of at most 512 characters.';
      if(!this.readPaths.has(action.path))return 'Read the candidate source before planning its test.';
      if(!action.query || !['html_reflection','path_construction','solidity_sequence','java_sequence','python_sequence','javascript_sequence'].includes(action.answer))return 'Select a function from the inspected source and a supported probe kind.';
      // Reject placeholder or invented probe targets before they consume an
      // expensive model turn or enter the dependency preparation sandbox.
      // A Solidity query must name a real Contract.function (or constructor).
      if(action.path.endsWith('.sol') && !/^[A-Za-z_$][\w$]*\.(?:[A-Za-z_$][\w$]*|constructor)$/.test(action.query))
        return 'Invalid Solidity probe target: query must be Contract.function using a declaration returned by outline_solidity. Do not use function, method, or guessed names.';
      if(!action.hypothesis?.trim())return 'State the suspected behavior and what observation would disprove it in hypothesis.';
      const mismatch=probeHypothesisMismatch(action.answer,action.hypothesis);
      if(mismatch)return mismatch;
      if(this.state.tested.includes(key(action)))return 'This probe already finished or was attempted. Use its observation; choose a different candidate or conclude with the permitted incomplete outcome.';
    }
    if(action.action==='verify_source' && this.state.pending && (action.path!==this.state.pending.path || action.query!==this.state.pending.query || action.answer!==this.state.pending.answer || !isDeepStrictEqual(action.sequence,this.state.pending.sequence)))
      return 'Execute the exact planned probe, including its sequence. No changed test was executed.';
    return null;
  }
  /** Explicitly close an orphaned selected scenario without claiming any
   * execution. Only the controller can issue this terminal disposition. */
  blockSelectedScenario(path:string,query:string,kind:string,reason:string){
    const id=this.scenarioMap.get(this.scenarioKey(path,query,kind));
    if(!id)return;
    const scenario=this.scenarios.get(id);
    if(scenario?.phase!=='resolved')this.scenarios.finish(id,'incomplete',reason);
  }
  /** Release a verifier that can no longer make progress. No fabricated test
   * or case ID is created; the blocked candidate is recorded as incomplete. */
  abortPending(reason:string) {
    const pending=this.state.pending;
    if(!pending || !reason.trim())return null;
    const id=this.scenarioMap.get(this.scenarioKey(pending.path,pending.query,pending.answer));
    if(id) {
      const scenario=this.scenarios.get(id);
      if(scenario && scenario.phase!=='resolved')
        this.scenarios.finish(id,'incomplete',reason);
    }
    this.observations.push({path:pending.path,function:pending.query,
      kind:pending.answer,status:'controller_blocked'});
    this.state.tested.push(key(pending));
    this.state.pending=null;
    this.recoveryProbe=null;
    this.feedback('Controller released an unexecutable plan: '+reason);
    return {path:pending.path,query:pending.query,kind:pending.answer};
  }
  plan(action:Action) {
    this.stageLock?.assertActionAllowed('plan_probe');
    this.preparedControllerPlan(action.path,action.query,action.answer);this.recoveryProbe=null;this.requiredProbePlanning=false;this.requiredProbeKind=null;this.requiredProbePlanningRejections=0;this.state.pending=action;this.duplicateProbeRejections=0;this.lastFeedback=''; }
  read(path:string) {
    this.stageLock?.assertActionAllowed('read_file');
    this.readPaths.add(path);this.latestSolidityPath=path.endsWith('.sol')?path:null; if(path===this.requiredSource)this.requiredSource=this.requiredSourceQueue.shift()||null; }
  observe(action:Action,output:string) {
    if(this.stageLock && ['verify_source','verify_python','read_file','read_solidity'].includes(action.action))
      this.stageLock.assertActionAllowed(action.action);
    if(action.action==='outline_solidity')this.outlinedPaths.add(action.path);
    if(action.action==='verify_source') {
      this.observeScenario(action,output);
      let result:any;try{result=JSON.parse(output);}catch{}
      this.observations.push({path:action.path,function:action.query,kind:action.answer,
        status:result?.status||'tool_error',...(typeof result?.evidenceFile==='string'?{evidenceFile:result.evidenceFile}:{}),...(typeof result?.behavior_observed==='boolean'?{behaviorObserved:result.behavior_observed}:{}),...(typeof result?.caseId==='string'?{caseId:result.caseId}: {})});
      this.state.tested.push(key(action));this.state.pending=null;this.state.inspections=0;this.pageTurns=0;
    } else {
      let page:any;try{page=JSON.parse(output);}catch{}
      // Only genuinely new source spans justify another continuation decision.
      // Errors, repeated pages and navigation assertions do not count as evidence.
      if(['read_file','read_solidity'].includes(action.action)) {
        this.pageTurns++;
        const spans=action.action==='read_solidity' && Array.isArray(page?.excerpts)
          ? page.excerpts.map((e:any)=>({path:e.path,start:e.start,end:e.end}))
          : [{path:action.path,start:page?.start,end:page?.end}];
        if(action.action==='read_file' && typeof action.path==='string' && (page?.nextOffset===null || Number.isSafeInteger(page?.nextOffset)))this.nextOffsets.set(action.path,page.nextOffset);
        for(const span of spans) {
          if(typeof span.path!=='string'||!Number.isSafeInteger(span.start)||!Number.isSafeInteger(span.end)||span.end<=span.start)continue;
          const id=JSON.stringify([span.path,span.start,span.end]);
          if(!this.readSpans.has(id)){this.readSpans.add(id);this.sourceProgress++;}
        }
      }
      if(output.includes('Repeated inspection action'))this.state.inspections=6;
      else if(action.action!=='read_file' || page?.nextOffset===null || output.startsWith('Tool error:'))this.state.inspections++;
    }
  }
  finalRejected(message:string) {
    // Keep the inspection checkpoint after a rejected conclusion. The model can
    // plan a probe, request specific missing context, or correct its final answer.
    this.lastFeedback=(message+' Do not re-read already completed pages or repeat unsupported candidate findings; use a different eligible source or a supported test.').slice(0,400);
    // Missing caller/source evidence requires a real read, even after the
    // investigation reached its hypothesis stage. Keep read spans and history.
    if(/Read the tested source file and the claimed caller file|Read the page containing the entire claimed caller line/.test(message)) {
      this.state.inspections=0;this.pageTurns=0;
    } else this.state.inspections=Math.max(6,this.state.inspections);
  }
  feedback(message:string,reopen=false) {this.lastFeedback=message.slice(0,400);if(reopen){this.state.inspections=0;this.pageTurns=0;}}
  snapshot() {return {sourceEvidenceByPath:[...this.sourceEvidence],scenarioLedger:this.scenarios.snapshot(),outlinedPaths:[...this.outlinedPaths],...this.state,
    stage:this.stageLock?({INDEX:'inspect',READ:'inspect',ANALYZE:'hypothesize',EXPERIMENT:'test',REVIEW:'review',REPORT:'review',COMPLETE:'review'} as const)[this.stageLock.currentStage]:this.state.stage,
    ...(this.stageLock?{lockedStage:this.stageLock.currentStage}:{}),pageTurns:this.pageTurns,sourceProgress:this.sourceProgress,decisions:this.decisions,priorNotes:this.priorNotes,readPaths:[...this.readPaths],observations:this.observations,verifiedEvidenceFocus:this.verifiedEvidenceFocus};}
}
