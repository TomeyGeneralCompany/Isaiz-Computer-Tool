import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {ControllerStageLock} from '../packages/security-solver/src/controller-stage-lock';
const hash=(s:string)=>createHash('sha256').update(s).digest('hex');
async function run(){
 const lock=new ControllerStageLock();
 assert.throws(()=>lock.recordRead({path:'source-1/A.sol',start:0,end:1,totalCharacters:1,text:'a'}),/STAGE_LOCKED/);
 lock.completeIndex([{path:'source-1/A.sol',characters:4,sha256:hash('abcd')},
  {path:'source-1/B.sol',characters:2,sha256:hash('ef')}]);
 assert.throws(()=>lock.assertActionAllowed('plan_probe'),/STAGE_LOCKED/);
 lock.discover('A.suspect');
 lock.recordRead({path:'source-1/A.sol',start:2,end:4,totalCharacters:4,text:'cd'});
 lock.recordRead({path:'source-1/A.sol',start:0,end:2,totalCharacters:4,text:'ab'});
 assert.equal(lock.coverage.completedCount,1);
 await assert.rejects(lock.completeReading(async p=>p.endsWith('A.sol')?'abcd':'ef'),/READ_INCOMPLETE/);
 lock.recordRead({path:'source-1/B.sol',start:0,end:1,totalCharacters:2,text:'e'});
 await assert.rejects(lock.completeReading(async p=>p.endsWith('A.sol')?'abcd':'ef'),/READ_INCOMPLETE/);
 lock.recordRead({path:'source-1/B.sol',start:1,end:2,totalCharacters:2,text:'f'});
 await assert.rejects(lock.completeReading(async()=> 'altered'),/SOURCE_CHANGED/);
 await lock.completeReading(async p=>p.endsWith('A.sol')?'abcd':'ef');
 assert.equal(lock.currentStage,'ANALYZE');
 assert.throws(()=>lock.completeAnalysis(),/ANALYSIS_PRECLASSIFICATION_INCOMPLETE/);
 lock.noteSourcePreclassified('source-1/A.sol','indexed-options-built');
 lock.noteSourcePreclassified('source-1/B.sol','indexed-options-built');
 assert.throws(()=>lock.assertActionAllowed('verify_source'),/STAGE_LOCKED/);
 lock.completeAnalysis();
 assert.equal(lock.currentStage,'EXPERIMENT');
 lock.requireCandidate('A.suspect');
 assert.throws(()=>lock.completeExperiments(),/INCOMPLETE/);
 lock.finishExperiment('A.suspect','observed');
 assert.deepEqual(lock.outcomeCounts,{observed:1,observation_only:0,
  not_observed:0,unsupported:0,incomplete:0,rejected:0,pending:0});
 lock.completeExperiments();
 assert.throws(()=>lock.completeReviews(),/INCOMPLETE/);
 lock.review('A.suspect');lock.completeReviews();
 lock.completeReport(true);
 assert.equal(lock.currentStage,'COMPLETE');
 // Source preclassification does not itself establish substantive model review.
 const assessed=new ControllerStageLock();
 const source='source-1/Analysis.sol',content='function deposit(uint256 amount) external {}';
 assessed.completeIndex([{path:source,characters:content.length,sha256:hash(content)}]);
 assessed.recordRead({path:source,start:0,end:content.length,totalCharacters:content.length,text:content});
 await assessed.completeReading(async()=>content);
 assessed.noteSourcePreclassified(source,'indexed-options-built');
 const commit='a'.repeat(40),idA=hash('lead:A'),idB=hash('lead:B');
 for(const [id,selector] of [[idA,'Analysis.deposit'],[idB,'Analysis.withdraw']]){
   assessed.registerAnalysisLead({id,sourceCommit:commit,sourceSha256:hash(content),path:source,selector});
 }
 assert.throws(()=>assessed.completeAnalysis(),new RegExp(idA));
 assert.equal(assessed.analysisProgress.pendingIds.length,2);
 const cited=source+':0-'+content.length+':'+hash(content);
 assessed.recordLeadAssessment(idA,{kind:'assessed',sourceEvidence:[cited],
   hypothesis:'An unauthorized sender changes protected state',disposition:'test',
   reason:'Controller inspected the exact declaration and authorized caller guard'},'model');
 assert.throws(()=>assessed.completeAnalysis(),new RegExp(idB));
 assessed.recordLeadAssessment(idB,{kind:'assessed',sourceEvidence:[cited],
   hypothesis:'No testable property established',disposition:'defer',
   reason:'No valid fixture for a full state transition is proven by source'},'model');
 assert.equal(assessed.analysisProgress.deferred,1);
 assessed.completeAnalysis();
 assert.equal(assessed.recordedAnalysisCertificate?.modelAssessed,2);
 assert.equal(assessed.recordedAnalysisCertificate?.status,'complete');
 const unavailable=new ControllerStageLock();
 unavailable.completeIndex([{path:source,characters:content.length,sha256:hash(content)}]);
 unavailable.recordRead({path:source,start:0,end:content.length,totalCharacters:content.length,text:content});
 await unavailable.completeReading(async()=>content);
 unavailable.noteSourcePreclassified(source,'indexed-options-built');
 unavailable.registerAnalysisLead({id:idA,sourceCommit:commit,sourceSha256:hash(content),path:source,selector:'Analysis.deposit'});
 assert.throws(()=>unavailable.completeAnalysis(),/ANALYSIS_INCOMPLETE/);
 unavailable.completeAnalysis('partial','qwen_model_unavailable_after_bounded_retries');
 assert.equal(unavailable.recordedAnalysisCertificate?.pendingIds[0],idA);
 assert.equal(unavailable.recordedAnalysisCertificate?.status,'partial');
 assert.equal(unavailable.currentStage,'EXPERIMENT');

 const policyLock=new ControllerStageLock(true);
 policyLock.completeIndex([{path:'source-1/A.sol',characters:4,sha256:hash('abcd')}]);
 policyLock.registerAuditPolicy('policy');
 policyLock.recordRead({path:'source-1/A.sol',start:0,end:4,totalCharacters:4,text:'abcd'});
 await assert.rejects(policyLock.completeReading(async path=>
   path==='audit-policy.txt'?'policy':'abcd'),/POLICY_INCOMPLETE/);
 policyLock.recordAuditPolicyPage({start:0,end:3,totalCharacters:6,text:'pol'});
 assert.equal(policyLock.auditPolicyNextOffset,3);
 await assert.rejects(policyLock.completeReading(async path=>
   path==='audit-policy.txt'?'policy':'abcd'),/POLICY_INCOMPLETE/);
 policyLock.recordAuditPolicyPage({start:3,end:6,totalCharacters:6,text:'icy'});
 assert.equal(policyLock.auditPolicyComplete,true);
 await assert.rejects(policyLock.completeReading(async path=>
   path==='audit-policy.txt'?'altered':'abcd'),/POLICY_CHANGED/);
 await policyLock.completeReading(async path=>
   path==='audit-policy.txt'?'policy':'abcd');
 assert.equal(policyLock.currentStage,'ANALYZE');
  console.log('Controller stage lock and complete source coverage PASSED');
}
void run().catch(e=>{console.error(e);process.exitCode=1;});
