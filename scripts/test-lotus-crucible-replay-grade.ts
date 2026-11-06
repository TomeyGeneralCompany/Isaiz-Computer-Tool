import assert from 'node:assert/strict';
import {adjudicateCrucibleReplay,type CrucibleReplayObservation} from './lotus-crucible-replay-grade';
import type {CrucibleAnswerKey} from './lotus-crucible-contract';

const sha='a'.repeat(64);
const key:CrucibleAnswerKey={
  challengeId:'sealed',seed:'private-seed',language:'python',kind:'vulnerable',
  defects:[{id:'d1',language:'python',entryPath:'entry.py',
    affectedPaths:['entry.py','middle.py','sink.py'],weakness:'test-only',
    reproduction:{kind:'source',selector:'run',expectedEffect:'observed'},
    requiredChains:[['entry.py','middle.py','sink.py']]}],
  falseLeads:[{id:'f1',language:'python',affectedPaths:['decoy.py'],
    safetyReason:'safe',replayExpectation:'no effect'}],
  negativeControls:[{id:'n1',language:'python',affectedPaths:['safe.py'],
    safetyReason:'guarded',replayExpectation:'blocked'}],
};
const claim:CrucibleReplayObservation={
  caseId:'d1',sourceSha256:sha,entryPath:'entry.py',
  chainPaths:['entry.py','middle.py','sink.py'],probeKind:'source',
  selector:'run',effect:'observed',executionId:'original',
  independentlyReplayed:false,authorizedScope:true,
};
const replay={...claim,executionId:'independent',independentlyReplayed:true};
const grade=(claims:CrucibleReplayObservation[],replays:CrucibleReplayObservation[],k=key)=>
  adjudicateCrucibleReplay({key:k,sourceSha256:sha,claims,independentObservations:replays});
assert.equal(grade([claim],[replay]).qualified,true);
assert.equal(grade([],[replay]).qualified,false);
assert.equal(grade([claim],[]).qualified,false);
assert.equal(grade([claim],[{...replay,effect:'different'}]).qualified,false);
assert.equal(grade([claim],[{...replay,executionId:'original'}]).qualified,false);
assert.equal(grade([claim],[{...replay,authorizedScope:false}]).qualified,false);
assert.equal(grade([{...claim,sourceSha256:'b'.repeat(64)}],[replay]).qualified,false);
assert.equal(grade([{...claim,chainPaths:['entry.py','sink.py']}],[replay]).qualified,false);
assert.equal(grade([{...claim,chainPaths:['entry.py','safe.py']}],[replay]).negativeControlViolations.length,1);
assert.equal(grade([{...claim,caseId:'invented'}],[replay]).unexpectedClaims.length,1);
assert.throws(()=>grade([claim,claim],[replay]),/duplicate/);
assert.throws(()=>grade([claim],[replay,replay]),/duplicate/);
const clean={...key,kind:'clean' as const,defects:[]};
assert.equal(grade([],[],clean).qualified,true);
assert.equal(grade([claim],[replay],clean).qualified,false);
console.log('Crucible independent replay adjudication fail-closed cases PASSED (contract tests, not runtime oracle)');
