import { Annotation, StateGraph, START, END } from '@langchain/langgraph';
import { isDeepStrictEqual } from 'node:util';
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
const key = (a:Action) => JSON.stringify([a.path,a.query,a.answer,a.sequence]);
export class InvestigationWorkflow {
  private state:typeof State.State={stage:'inspect',inspections:0,pending:null,tested:[]};
  private readPaths=new Set<string>();
  private requiredSource:string|null=null;
  private recoveryProbe:{path:string;query:string;kind:string}|null=null;
  private duplicateProbeRejections=0;
  private observations:Array<{path:string;function:string;kind:string;status:string;caseId?:string;evidenceFile?:string;behaviorObserved?:boolean}>=[];
  private lastFeedback='';
  private decisions:Array<{path:string;question:string;offset:number}>=[];
  private priorNotes:string[]=[];
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
    this.priorNotes=saved.notes.filter((n:unknown)=>typeof n==='string').slice(-12).map((n:string)=>n.slice(0,400));
  }
  memory() {
    return {version:1,notes:[...this.priorNotes,
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
    if(this.pageTurns>=8)this.state.inspections=Math.max(6,this.state.inspections);
    this.state=await graph.invoke(this.state);
    if(this.requiredSource)return {action:['read_file'],path:[this.requiredSource]};
    if(this.recoveryProbe)return {action:['plan_probe'],path:[this.recoveryProbe.path],query:[this.recoveryProbe.query],answer:[this.recoveryProbe.kind]};
    if(this.duplicateProbeRejections>=2 && !this.state.pending)return {action:['read_file','read_solidity','outline_solidity','search_files','list_files','plan_probe','continue_inspection','final']};
    if(this.state.pending) {
      const p=this.state.pending;
      return {action:['verify_source'],path:[p.path],query:[p.query],answer:[p.answer]};
    }
    return {action:this.state.stage==='hypothesize' ? ['plan_probe','continue_inspection','final'] :
      ['read_file','read_solidity','outline_solidity','search_files','list_files','plan_probe','final']};
  }
  note():string {
    const note={unansweredQuestion:this.decisions.length?{...this.decisions.at(-1)!,path:this.decisions.at(-1)!.path.slice(0,160),question:this.decisions.at(-1)!.question.slice(0,250)}:undefined,priorNavigation:this.priorNotes.slice(-1).map(n=>n.slice(0,200)),pageTurns:this.pageTurns,stage:this.state.stage,inspectionsSinceDecision:this.state.inspections,
      recentReadPaths:[...this.readPaths].slice(-3).map(p=>p.slice(0,160)),nextUnreadPages:[...this.nextOffsets].filter(([,offset])=>offset!==null).slice(-3).map(([path,offset])=>({path:path.slice(0,160),offset})),pending:this.state.pending ? {path:this.state.pending.path.slice(0,160),function:this.state.pending.query,kind:this.state.pending.answer} : null,
      observations:this.observations.slice(-2).map(o=>({...o,path:o.path.slice(0,160)})),feedback:this.lastFeedback.slice(0,240),
      instruction:this.state.pending?'Execute the planned probe with exactly its path, function, kind and sequence.':
        'Read relevant source, then plan_probe with path, query=function, answer=probe kind, hypothesis=claim AND disproof condition. After six inspections or eight source pages, choose plan_probe, continue_inspection with a specific unanswered question in hypothesis and the next path/offset/query, or an incomplete final. Continue only to obtain that missing evidence; no forced unrelated test. A failed or unsupported verification is not proof of absence or presence. After inspecting recorded evidence, change candidate or request specific missing context; do not repeat completed evidence pages. Read recorded evidenceFile pages when an observation leaves context instead of repeating its probe. After testing inspect caller/mitigations before reporting; observations alone are not findings.'};
    while(JSON.stringify(note).length>1800 && note.priorNavigation.length)note.priorNavigation.shift();
    while(JSON.stringify(note).length>1800 && note.recentReadPaths.length)note.recentReadPaths.shift();
    while(JSON.stringify(note).length>1800 && note.nextUnreadPages.length)note.nextUnreadPages.shift();
    while(JSON.stringify(note).length>1800 && note.observations.length)note.observations.shift();
    if(JSON.stringify(note).length>1800){note.unansweredQuestion=undefined;note.feedback=note.feedback.slice(0,100);}
    return JSON.stringify(note);
  }
  requireProbe(path:string,query:string,kind:string) {
    this.recoveryProbe={path,query,kind};
    this.feedback('Unverified proposed finding: plan this inspected declared function with a concrete disproof condition, then execute verify_source. If the probe is unsupported, continue with another candidate.');
  }
  clearProbeRecovery() {this.recoveryProbe=null;}
  rejectedDuplicateProbe() {this.duplicateProbeRejections++;this.feedback('The already attempted probe cannot be repeated. Return outcome=no_testable_candidate with a specific reason and findings=[]; do not claim an unverified vulnerability.');}
  requireSource(path:string) {this.requiredSource=path;this.feedback('Read '+path+' before planning its test.',true);}
  validate(action:Action):string|null {
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
      if(!action.query || !['html_reflection','path_construction','solidity_sequence'].includes(action.answer))return 'Select a function from the inspected source and a supported probe kind.';
      // Reject placeholder or invented probe targets before they consume an
      // expensive model turn or enter the dependency preparation sandbox.
      // A Solidity query must name a real Contract.function (or constructor).
      if(action.path.endsWith('.sol') && !/^[A-Za-z_$][\w$]*\.(?:[A-Za-z_$][\w$]*|constructor)$/.test(action.query))
        return 'Invalid Solidity probe target: query must be Contract.function using a declaration returned by outline_solidity. Do not use function, method, or guessed names.';
      if(!action.hypothesis?.trim())return 'State the suspected behavior and what observation would disprove it in hypothesis.';
      if(this.state.tested.includes(key(action)))return 'This probe already finished or was attempted. Use its observation; choose a different candidate or conclude with the permitted incomplete outcome.';
    }
    if(action.action==='verify_source' && this.state.pending && (action.path!==this.state.pending.path || action.query!==this.state.pending.query || action.answer!==this.state.pending.answer || !isDeepStrictEqual(action.sequence,this.state.pending.sequence)))
      return 'Execute the exact planned probe, including its sequence. No changed test was executed.';
    return null;
  }
  plan(action:Action) { this.recoveryProbe=null;this.state.pending=action;this.duplicateProbeRejections=0;this.lastFeedback=''; }
  read(path:string) { this.readPaths.add(path); if(path===this.requiredSource)this.requiredSource=null; }
  observe(action:Action,output:string) {
    if(action.action==='verify_source') {
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
    this.state.inspections=Math.max(6,this.state.inspections);
  }
  feedback(message:string,reopen=false) {this.lastFeedback=message.slice(0,400);if(reopen){this.state.inspections=0;this.pageTurns=0;}}
  snapshot() {return {...this.state,pageTurns:this.pageTurns,sourceProgress:this.sourceProgress,decisions:this.decisions,priorNotes:this.priorNotes,readPaths:[...this.readPaths],observations:this.observations};}
}
