import {ControllerSourceCoverage,type IndexedSource,type SourceRead} from './controller-stage-evidence';
export type Stage='INDEX'|'READ'|'ANALYZE'|'EXPERIMENT'|'REVIEW'|'REPORT'|'COMPLETE';
export type Outcome='observed'|'not_observed'|'unsupported'|'incomplete'|'rejected';
const actions:Record<Stage,ReadonlySet<string>>={
 INDEX:new Set(['index_source']),
 READ:new Set(['read_file','read_solidity','outline_solidity','search_files','list_files','continue_inspection']),
 ANALYZE:new Set(['discover_experiment','finalize_analysis']),
 EXPERIMENT:new Set(['plan_probe','probe_intent','verify_source','verify_python']),
 REVIEW:new Set(['independent_review']),
 REPORT:new Set(['final']),
 COMPLETE:new Set()
};
export class ControllerStageLock {
 readonly coverage=new ControllerSourceCoverage();
 private stage:Stage='INDEX';
 private candidates=new Map<string,Outcome|null>();
 private reviews=new Map<string,boolean>();
 private finalized=false;
 private analyzed=new Map<string,'complete'|'unsupported'>();
 get currentStage(){return this.stage;}
 get candidateCount(){return this.candidates.size;}
 get completedCount(){return [...this.candidates.values()].filter(x=>x!==null).length;}
 assertActionAllowed(action:string){
   if(!actions[this.stage].has(action))throw new Error('STAGE_LOCKED: '+this.stage+' forbids '+action);
 }
 private advance(expected:Stage,next:Stage){
   if(this.stage!==expected)throw new Error('INVALID_STAGE_TRANSITION: '+this.stage+' -> '+next);
   this.stage=next;
 }
 completeIndex(files:readonly IndexedSource[]){
   this.assertActionAllowed('index_source');
   this.coverage.finishIndex(files);this.advance('INDEX','READ');
 }
 recordRead(page:SourceRead){
   this.assertActionAllowed('read_file');this.coverage.record(page);
 }
 async completeReading(read:(p:string)=>Promise<string>){
   if(this.stage!=='READ')throw new Error('READ_STAGE_REQUIRED');
   await this.coverage.assertUnchanged(read);this.advance('READ','ANALYZE');
 }
 discover(id:string){
   if(this.stage!=='READ'&&this.stage!=='ANALYZE')throw new Error('DISCOVERY_STAGE_LOCKED');
   if(this.finalized||!id)throw new Error('DISCOVERY_CLOSED');
   if(!this.candidates.has(id))this.candidates.set(id,null);
 }
 noteAnalyzed(path:string,status:'complete'|'unsupported'){
   if(this.stage!=='ANALYZE'||!this.coverage.hasIndexed(path)||this.analyzed.has(path))
     throw new Error('INVALID_ANALYSIS_RECORD');
   this.analyzed.set(path,status);
 }
 completeAnalysis(){
   if(this.stage!=='ANALYZE'||this.analyzed.size!==this.coverage.count)
     throw new Error('ANALYSIS_INCOMPLETE');
   this.finalized=true;this.advance('ANALYZE','EXPERIMENT');
 }
 requireCandidate(id:string){
   this.assertActionAllowed('plan_probe');
   if(!this.candidates.has(id)||this.candidates.get(id)!==null)throw new Error('EXPERIMENT_NOT_QUEUED');
 }
 finishExperiment(id:string,result:Outcome){
   this.assertActionAllowed('verify_source');
   if(!this.candidates.has(id)||this.candidates.get(id)!==null)throw new Error('EXPERIMENT_NOT_PENDING');
   this.candidates.set(id,result);
   if(result==='observed')this.reviews.set(id,false);
 }
 completeExperiments(){
   if(this.stage!=='EXPERIMENT'||this.completedCount!==this.candidateCount)
     throw new Error('EXPERIMENTS_INCOMPLETE');
   this.advance('EXPERIMENT','REVIEW');
 }
 review(id:string){
   this.assertActionAllowed('independent_review');
   if(this.reviews.get(id)!==false)throw new Error('REVIEW_NOT_PENDING');
   this.reviews.set(id,true);
 }
 completeReviews(){
   if(this.stage!=='REVIEW'||[...this.reviews.values()].some(x=>!x))
     throw new Error('REVIEWS_INCOMPLETE');
   this.advance('REVIEW','REPORT');
 }
 completeReport(accepted:boolean){
   this.assertActionAllowed('final');
   if(!accepted)throw new Error('REPORT_REJECTED');
   this.advance('REPORT','COMPLETE');
 }
}
