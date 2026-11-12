import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {ControllerStageLock} from '../packages/security-solver/src/controller-stage-lock';
const digest=(s:string)=>createHash('sha256').update(s).digest('hex');
async function testCoverage(){
 const lock=new ControllerStageLock();
 const sources=Array.from({length:91},(_,i)=>({
   path:'source-1/contracts/File'+i+'.sol',sha256:digest('abcdef'),characters:6
 }));
 lock.completeIndex(sources);
 for(const item of sources.slice(0,90))
   lock.recordRead({path:item.path,start:0,end:6,totalCharacters:6,text:'abcdef'});
 assert.equal(lock.coverage.completedCount,90);
 await assert.rejects(lock.completeReading(async()=> 'abcdef'),/READ_INCOMPLETE/);
 lock.recordRead({path:sources[90].path,start:0,end:2,totalCharacters:6,text:'ab'});
 lock.recordRead({path:sources[90].path,start:4,end:6,totalCharacters:6,text:'ef'});
 await assert.rejects(lock.completeReading(async()=> 'abcdef'),/READ_INCOMPLETE/);
 lock.recordRead({path:sources[90].path,start:2,end:4,totalCharacters:6,text:'cd'});
 await lock.completeReading(async()=> 'abcdef');
 assert.equal(lock.currentStage,'ANALYZE');
 console.log('91/91 full-index byte range coverage PASSED');
}
void testCoverage().catch(e=>{console.error(e);process.exitCode=1;});
