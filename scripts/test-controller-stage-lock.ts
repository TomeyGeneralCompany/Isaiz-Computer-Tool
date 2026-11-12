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
 assert.throws(()=>lock.assertActionAllowed('verify_source'),/STAGE_LOCKED/);
 lock.completeAnalysis();
 assert.equal(lock.currentStage,'EXPERIMENT');
 lock.requireCandidate('A.suspect');
 assert.throws(()=>lock.completeExperiments(),/INCOMPLETE/);
 lock.finishExperiment('A.suspect','observed');
 lock.completeExperiments();
 assert.throws(()=>lock.completeReviews(),/INCOMPLETE/);
 lock.review('A.suspect');lock.completeReviews();
 lock.completeReport(true);
 assert.equal(lock.currentStage,'COMPLETE');
 console.log('Controller stage lock and complete source coverage PASSED');
}
void run().catch(e=>{console.error(e);process.exitCode=1;});
