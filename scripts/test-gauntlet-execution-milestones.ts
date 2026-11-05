import assert from 'node:assert/strict';
import {gauntletExecutionMilestones} from './gauntlet-execution-milestones';
const expected={file:'src/renderer.cjs',selector:'render'};
const guided=[
  '[INITIAL_SOURCE_READ] {"path":"source-1/src/renderer.cjs","start":0,"end":100,"nextOffset":null}',
  '[GUIDED_SOURCE_PROBE] {"path":"source-1/src/renderer.cjs","function":"render","status":"behavior_observed","evidenceFile":"e.json"}'
].join('\n');
const result=gauntletExecutionMilestones(guided,expected);
assert.equal(result.sourceRead,true);
assert.equal(result.relevantCandidateInspected,true);
assert.equal(result.probePlanned,true);
assert.equal(result.probeExecuted,true);
assert.equal(result.probeCompleted,true);
assert.equal(result.hypothesisExamined,true);
const blocked=[
  '[READ_OK] source-1/contracts/Adapter.sol offset=0 end=100 nextOffset=null',
  '[PROBE_PLANNED] {"path":"source-1/contracts/Adapter.sol","query":"Adapter.rotateOperator","answer":"solidity_sequence"}',
  '[PROBE_RESULT] {"path":"source-1/contracts/Adapter.sol","function":"Adapter.rotateOperator","status":"probe_failed"}'
].join('\n');
const fail=gauntletExecutionMilestones(blocked,{file:'contracts/Authority.sol',selector:'rotateOperator'});
assert.equal(fail.sourceRead,true);
assert.equal(fail.relevantCandidateInspected,false);
assert.equal(fail.probePlanned,true);
assert.equal(fail.probeExecuted,true);
assert.equal(fail.probeCompleted,false);
assert.equal(fail.hypothesisExamined,false);
assert.equal(fail.counters.failed,1);
const observation=gauntletExecutionMilestones([
 '[READ_OK] source-1/contracts/Authority.sol offset=0 end=100 nextOffset=null',
 '[PROBE_RESULT] {"path":"source-1/contracts/Authority.sol","function":"Authority.rotateOperator","status":"observation_only"}'
].join('\n'),{file:'contracts/Authority.sol',selector:'Authority.rotateOperator'});
assert.equal(observation.probeCompleted,true);
assert.equal(observation.targetProbeCompleted,true);
assert.equal(observation.hypothesisExamined,true);
// An observation alone is not a reviewed security finding; the final grade
// still uses reviewer/case/answer-key matching.
console.log('Gauntlet controller-owned grading and failed-vs-complete probe regression PASSED');
