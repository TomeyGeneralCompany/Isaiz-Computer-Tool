import assert from 'node:assert/strict';
import {advanceBountyProgress,idleBountyExpired,type BountyProgress} from './one-bounty-progress';

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
console.log('Progress-based one-bounty timeout checks PASSED');
