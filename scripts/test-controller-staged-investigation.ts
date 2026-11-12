import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {ControllerStageLock} from '../packages/security-solver/src/controller-stage-lock';
const hash=(s:string)=>createHash('sha256').update(s).digest('hex');
async function test(){
 const stages=new ControllerStageLock();
 const content='test';
 stages.completeIndex([{path:'source-1/A.sol',sha256:hash(content),characters:4}]);
 stages.discover('first');stages.discover('second');
 assert.throws(()=>stages.assertActionAllowed('verify_source'),/STAGE_LOCKED/);
 stages.recordRead({path:'source-1/A.sol',start:0,end:4,totalCharacters:4});
 await stages.completeReading(async()=>content);
 assert.throws(()=>stages.assertActionAllowed('plan_probe'),/STAGE_LOCKED/);
 stages.completeAnalysis();stages.requireCandidate('first');
 stages.finishExperiment('first','unsupported');
 assert.throws(()=>stages.completeExperiments(),/EXPERIMENTS_INCOMPLETE/);
 stages.finishExperiment('second','observed');
 stages.completeExperiments();
 assert.throws(()=>stages.assertActionAllowed('final'),/STAGE_LOCKED/);
 stages.review('second');stages.completeReviews();
 stages.completeReport(true);
 assert.deepEqual(stages.currentStage,'COMPLETE');
 console.log('Experiment exhaust/review/report stage locks PASSED');
}
void test().catch(e=>{console.error(e);process.exitCode=1;});
