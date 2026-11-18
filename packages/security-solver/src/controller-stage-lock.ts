import {ControllerSourceCoverage,type IndexedSource,type SourceRead} from './controller-stage-evidence';
import {createHash} from 'node:crypto';
export type Stage='INDEX'|'READ'|'ANALYZE'|'EXPERIMENT'|'REVIEW'|'REPORT'|'COMPLETE';
export type Outcome='observed'|'observation_only'|'not_observed'|'unsupported'|'incomplete'|'rejected';
export type LeadDisposition='test'|'defer'|'no-testable-property';
export type LeadAssessment={
  id:string;sourceCommit:string;sourceSha256:string;path:string;selector:string;
  state:
   | {kind:'pending'}
   | {kind:'assessed';sourceEvidence:string[];hypothesis:string;disposition:LeadDisposition;reason:string}
   | {kind:'blocked';sourceEvidence:string[];missing:string[];reason:string};
  assessedBy:'model'|'controller'|null;
};
export type AnalysisCertificate={
  status:'complete'|'partial';reason:string;selected:number;assessed:number;blocked:number;
  pendingIds:string[];sourcePreclassified:number;modelAssessed:number;
};
const actions:Record<Stage,ReadonlySet<string>>={
 INDEX:new Set(['index_source']),
 READ:new Set(['read_file','read_solidity','outline_solidity','search_files','list_files','continue_inspection']),
 ANALYZE:new Set(['assess_lead','defer_lead','request_source_context','discover_experiment','finalize_analysis']),
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
 private sourcePreclassified=new Map<string,'indexed-options-built'|'source-unavailable'>();
 private leads=new Map<string,LeadAssessment>();
 private analysisCertificate:AnalysisCertificate|null=null;
 private policy:{sha256:string;characters:number;pages:Array<[number,number,string]>}|null=null;
 constructor(readonly auditPolicyRequired=false){}
 registerAuditPolicy(content:string):void {
   if(!this.auditPolicyRequired||this.stage!=='READ'||this.policy)
     throw new Error('POLICY_REGISTRATION_FORBIDDEN');
   this.policy={sha256:createHash('sha256').update(content).digest('hex'),
     characters:content.length,pages:[]};
 }
 recordAuditPolicyPage(page:{start:number;end:number;totalCharacters:number;text:string}):void {
   this.assertActionAllowed('read_file');
   const record=this.policy;
   if(!record||page.totalCharacters!==record.characters||
     !Number.isSafeInteger(page.start)||!Number.isSafeInteger(page.end)||
     page.start<0||page.end<page.start||page.end>record.characters||
     page.text.length!==page.end-page.start)throw new Error('POLICY_INVALID_PAGE');
   record.pages.push([page.start,page.end,createHash('sha256').update(page.text).digest('hex')]);
 }
 get auditPolicyComplete():boolean {
   if(!this.auditPolicyRequired)return true;
   const record=this.policy;
   if(!record||!record.pages.length)return false;
   if(record.characters===0)return record.pages.some(([a,b])=>a===0&&b===0);
   return this.auditPolicyNextOffset===record.characters;
 }
 get auditPolicyNextOffset():number {
   const record=this.policy;
   if(!record)throw new Error('POLICY_NOT_REGISTERED');
   let cursor=0;
   for(const [start,end] of [...record.pages].sort((a,b)=>a[0]-b[0])){
     if(start>cursor)break;
     cursor=Math.max(cursor,end);
   }
   return cursor;
 }
 async assertAuditPolicyUnchanged(read:(path:string)=>Promise<string>):Promise<void>{
   if(!this.auditPolicyComplete)throw new Error('POLICY_INCOMPLETE');
   if(!this.auditPolicyRequired)return;
   const record=this.policy!;
   const content=await read('audit-policy.txt');
   if(content.length!==record.characters||
     createHash('sha256').update(content).digest('hex')!==record.sha256)
     throw new Error('POLICY_CHANGED');
   for(const [start,end,sha] of record.pages)
     if(createHash('sha256').update(content.slice(start,end)).digest('hex')!==sha)
       throw new Error('POLICY_PAGE_MISMATCH');
 }
 get currentStage(){return this.stage;}
 get candidateCount(){return this.candidates.size;}
 get completedCount(){return [...this.candidates.values()].filter(x=>x!==null).length;}
 get outcomeCounts(){
   const counts={observed:0,observation_only:0,not_observed:0,unsupported:0,incomplete:0,rejected:0,pending:0};
   for(const outcome of this.candidates.values()) {
     if(outcome===null)counts.pending++;
     else counts[outcome]++;
   }
   return counts;
 }
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
   await this.coverage.assertUnchanged(read);
   await this.assertAuditPolicyUnchanged(read);
   this.advance('READ','ANALYZE');
 }
 discover(id:string){
   if(this.stage!=='READ'&&this.stage!=='ANALYZE')throw new Error('DISCOVERY_STAGE_LOCKED');
   if(this.finalized||!id)throw new Error('DISCOVERY_CLOSED');
   if(!this.candidates.has(id))this.candidates.set(id,null);
 }
 noteSourcePreclassified(path:string,status:'indexed-options-built'|'source-unavailable'){
    if(this.stage!=='ANALYZE'||!this.coverage.hasIndexed(path)||this.sourcePreclassified.has(path))
      throw new Error('INVALID_SOURCE_PRECLASSIFICATION');
    this.sourcePreclassified.set(path,status);
  }
  registerAnalysisLead(lead:Omit<LeadAssessment,'state'|'assessedBy'>){
    if(this.stage!=='ANALYZE'||!this.coverage.hasIndexed(lead.path)||
      !/^[a-f0-9]{40}$/.test(lead.sourceCommit)||!/^[a-f0-9]{64}$/.test(lead.sourceSha256)||
      !lead.id||!lead.selector||this.leads.has(lead.id))
      throw new Error('INVALID_ANALYSIS_LEAD');
    this.leads.set(lead.id,{...lead,state:{kind:'pending'},assessedBy:null});
  }
  get analysisLeads():LeadAssessment[]{return [...this.leads.values()].map(lead=>structuredClone(lead));}
  get analysisProgress(){const leads=[...this.leads.values()];return {
    selected:leads.length,assessed:leads.filter(x=>x.state.kind==='assessed').length,
    blocked:leads.filter(x=>x.state.kind==='blocked').length,
    pendingIds:leads.filter(x=>x.state.kind==='pending').map(x=>x.id),
    modelAssessed:leads.filter(x=>x.assessedBy==='model').length
  };}
  recordLeadAssessment(id:string,assessment:Extract<LeadAssessment['state'],{kind:'assessed'|'blocked'}>,by:'model'|'controller'){
    if(this.stage!=='ANALYZE')throw new Error('LEAD_ASSESSMENT_STAGE_CLOSED');
    const lead=this.leads.get(id);
    if(!lead||lead.state.kind!=='pending')throw new Error('LEAD_NOT_PENDING: '+id);
    if(!assessment.reason.trim()||!assessment.sourceEvidence.length||
      assessment.sourceEvidence.some(x=>!x.trim()||x.length>300))
      throw new Error('LEAD_ASSESSMENT_EVIDENCE_REQUIRED: '+id);
    if(assessment.kind==='assessed'&&!assessment.hypothesis.trim())
      throw new Error('LEAD_ASSESSMENT_HYPOTHESIS_REQUIRED: '+id);
    if(assessment.kind==='blocked'&&!assessment.missing.length)
      throw new Error('LEAD_ASSESSMENT_MISSING_REQUIRED: '+id);
    this.leads.set(id,{...lead,state:structuredClone(assessment),assessedBy:by});
  }
  analysisClosureCertificate(status:'complete'|'partial'='complete',reason=''):AnalysisCertificate{
    const counts=this.analysisProgress;
    return {status,reason,...counts,sourcePreclassified:this.sourcePreclassified.size};
  }
  get recordedAnalysisCertificate(){return this.analysisCertificate ? {...this.analysisCertificate,pendingIds:[...this.analysisCertificate.pendingIds]} : null;}
  completeAnalysis(status:'complete'|'partial'='complete',reason=''){
    if(this.stage!=='ANALYZE'||this.sourcePreclassified.size!==this.coverage.count)
      throw new Error('ANALYSIS_PRECLASSIFICATION_INCOMPLETE');
    const cert=this.analysisClosureCertificate(status,reason);
    if(status==='complete'&&cert.pendingIds.length)
      throw new Error('ANALYSIS_INCOMPLETE: pending lead IDs '+cert.pendingIds.join(','));
    if(status==='partial'&&!reason.trim())throw new Error('ANALYSIS_PARTIAL_REASON_REQUIRED');
    this.analysisCertificate=cert;
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
   this.reviews.set(id,false);
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
