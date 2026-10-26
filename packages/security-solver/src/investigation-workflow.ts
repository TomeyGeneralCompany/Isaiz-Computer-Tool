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
  private observations:Array<{path:string;function:string;kind:string;status:string;caseId?:string}>=[];
  private lastFeedback='';
  async constraints() {
    this.state=await graph.invoke(this.state);
    if(this.state.pending) {
      const p=this.state.pending;
      return {action:['verify_source'],path:[p.path],query:[p.query],answer:[p.answer]};
    }
    return {action:this.state.stage==='hypothesize' ? ['plan_probe','final'] :
      ['read_file','read_solidity','outline_solidity','search_files','list_files','plan_probe','final']};
  }
  note():string {
    const note={stage:this.state.stage,inspectionsSinceDecision:this.state.inspections,
      recentReadPaths:[...this.readPaths].slice(-3).map(p=>p.slice(0,160)),pending:this.state.pending ? {path:this.state.pending.path.slice(0,160),function:this.state.pending.query,kind:this.state.pending.answer} : null,
      observations:this.observations.slice(-2).map(o=>({...o,path:o.path.slice(0,160)})),feedback:this.lastFeedback,
      instruction:this.state.pending?'Execute the planned probe with exactly its path, function, kind and sequence.':
        'Read relevant source, then plan_probe with path, query=function, answer=probe kind, hypothesis=claim AND disproof condition. After six completed inspections choose a testable hypothesis or a truthful incomplete final outcome. After testing inspect caller/mitigations before reporting; observations alone are not findings.'};
    while(JSON.stringify(note).length>1800 && note.recentReadPaths.length)note.recentReadPaths.shift();
    while(JSON.stringify(note).length>1800 && note.observations.length)note.observations.shift();
    return JSON.stringify(note);
  }
  validate(action:Action):string|null {
    if(action.action==='plan_probe') {
      if(action.path.length>512)return 'Choose a workspace-relative source path of at most 512 characters.';
      if(!this.readPaths.has(action.path))return 'Read the candidate source before planning its test.';
      if(!action.query || !['html_reflection','path_construction','solidity_sequence'].includes(action.answer))return 'Select a function from the inspected source and a supported probe kind.';
      if(!action.hypothesis?.trim())return 'State the suspected behavior and what observation would disprove it in hypothesis.';
      if(this.state.tested.includes(key(action)))return 'This probe already finished or was attempted. Use its observation; choose a different candidate or conclude with the permitted incomplete outcome.';
    }
    if(action.action==='verify_source' && this.state.pending && (action.path!==this.state.pending.path || action.query!==this.state.pending.query || action.answer!==this.state.pending.answer || !isDeepStrictEqual(action.sequence,this.state.pending.sequence)))
      return 'Execute the exact planned probe, including its sequence. No changed test was executed.';
    return null;
  }
  plan(action:Action) { this.state.pending=action;this.lastFeedback=''; }
  read(path:string) { this.readPaths.add(path); }
  observe(action:Action,output:string) {
    if(action.action==='verify_source') {
      let result:any;try{result=JSON.parse(output);}catch{}
      this.observations.push({path:action.path,function:action.query,kind:action.answer,
        status:result?.status||'tool_error',...(typeof result?.caseId==='string'?{caseId:result.caseId}: {})});
      this.state.tested.push(key(action));this.state.pending=null;this.state.inspections=0;
    } else {
      let page:any;try{page=JSON.parse(output);}catch{}
      // Continuing a large source file is real progress, not six separate decisions.
      if(output.includes('Repeated inspection action'))this.state.inspections=6;
      else if(action.action!=='read_file' || page?.nextOffset===null || output.startsWith('Tool error:'))this.state.inspections++;
    }
  }
  feedback(message:string,reopen=false) {this.lastFeedback=message.slice(0,400);if(reopen)this.state.inspections=0;}
  snapshot() {return {...this.state,readPaths:[...this.readPaths],observations:this.observations};}
}
