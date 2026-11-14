import assert from 'node:assert/strict';
import {
  advanceBountyProgress,
  consumeTelemetryChunk,
  idleBountyExpired,
  pickLatestProgressEvent,
  type BountyProgress
} from './one-bounty-progress';

const start:BountyProgress={lastActivityAt:0,logPath:null,logBytes:0,stage:'starting'};
const quiet=advanceBountyProgress(start,120_000,{});
assert.equal(quiet.lastActivityAt,0,'A periodic polling tick is not progress');
assert.equal(idleBountyExpired(quiet,35*60_000,35),true);
const discovered=advanceBountyProgress(quiet,180_000,{logPath:'/logs/local-hunt-1.log',logBytes:24,stage:'hunting'});
assert.equal(discovered.lastActivityAt,180_000);
const generating=advanceBountyProgress(discovered,35*60_000,{logPath:discovered.logPath,logBytes:400,stage:'hunting'});
assert.equal(generating.lastActivityAt,35*60_000,'Log growth extends the active investigation');
assert.equal(idleBountyExpired(generating,60*60_000,35),false);
const unchanged=advanceBountyProgress(generating,61*60_000,{logPath:generating.logPath,logBytes:400,stage:'hunting'});
assert.equal(unchanged.lastActivityAt,35*60_000,'Repeated check is not evidence of progress');
assert.equal(idleBountyExpired(unchanged,70*60_000,35),true);
const review=advanceBountyProgress(generating,65*60_000,{logPath:'/logs/local-review-1.log',logBytes:10,stage:'reviewing'});
assert.equal(review.lastActivityAt,65*60_000,'Transition to review is progress');

// Telemetry extraction and formatting checks
const chunk1=[
  'contract UntrustedSource { function withdraw() public {} }',
  '[STAGE_UNLOCK] INDEX -> READ',
  '[OLLAMA] turn 1/120: request started; model=qwen3:4b',
  '[MODEL_PROGRESS] {"turn":1,"elapsedMs":5000,"tokens":32}',
  '[MODEL_PROGRESS] {"turn":1,"elapsedMs":10000,"tokens":64}',
  '[OLLAMA] turn 1: response received in 11200ms',
  '[MODEL_ACTION] {"action":"read_file","path":"contracts/DInterest.sol","offset":0}',
  '[STAGE_READ_CURSOR] {"path":"contracts/DInterest.sol","offset":2000,"completed":1,"total":91}'
].join('\n')+'\n[CONTROLLER_OWNED_';

const firstConsume=consumeTelemetryChunk('',chunk1,{maxLines:12});
assert.equal(firstConsume.remainder,'[CONTROLLER_OWNED_');
assert.equal(firstConsume.omitted,0);
assert.deepEqual(firstConsume.lines,[
  '[STAGE_UNLOCK] INDEX -> READ',
  '[OLLAMA] turn 1/120: request started; model=qwen3:4b',
  '[OLLAMA] turn 1: response received in 11200ms',
  '[MODEL_ACTION] {"action":"read_file","path":"contracts/DInterest.sol","offset":0}',
  '[STAGE_READ_CURSOR] {"path":"contracts/DInterest.sol","offset":2000,"completed":1,"total":91}'
]);

const chunk2='ACTION] {"action":"probe","path":"contracts/DInterest.sol","token":"github_pat_1234567890"}\n[PROBE_RESULT] {"status":"reproduced","caseId":"case-1"}\n';
const secondConsume=consumeTelemetryChunk(firstConsume.remainder,chunk2,{maxLines:12});
assert.equal(secondConsume.remainder,'');
assert.equal(secondConsume.lines.length,2);
assert.ok(secondConsume.lines[0].includes('github_pat_[REDACTED]'));
assert.ok(!secondConsume.lines[0].includes('github_pat_1234567890'));
assert.equal(secondConsume.lines[1],'[PROBE_RESULT] {"status":"reproduced","caseId":"case-1"}');

// Burst capping keeps latest telemetry lines without flooding CI output
const burst=Array.from({length:20},(_,i)=>`[READ_OK] contracts/File${i}.sol offset=0 end=1000`).join('\n')+'\n';
const capped=consumeTelemetryChunk('',burst,{maxLines:5});
assert.equal(capped.omitted,15);
assert.equal(capped.lines.length,5);
assert.equal(capped.lines[0],'[READ_OK] contracts/File15.sol offset=0 end=1000');
assert.equal(capped.lines[4],'[READ_OK] contracts/File19.sol offset=0 end=1000');

// Latest event prefers concrete action/stage over subsequent [OLLAMA] / [MODEL_PROGRESS] noise
assert.equal(
  pickLatestProgressEvent('[MODEL_ACTION] {"action":"probe"}\n[OLLAMA] turn 2/120: request started\n[MODEL_PROGRESS] {"turn":2}\n'),
  '[MODEL_ACTION] {"action":"probe"}'
);
assert.equal(
  pickLatestProgressEvent('raw line without tag\n[MODEL_PROGRESS] {"turn":2,"elapsedMs":5000}\n'),
  '[MODEL_PROGRESS] {"turn":2,"elapsedMs":5000}'
);
assert.equal(
  pickLatestProgressEvent('raw line without any telemetry tag'),
  ''
);

console.log('Progress-based one-bounty timeout checks PASSED');
