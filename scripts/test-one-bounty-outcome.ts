import assert from 'node:assert/strict';
import {oneBountyOutcomeExitCode} from './one-bounty-outcome';
assert.equal(oneBountyOutcomeExitCode('completed','completed'),0);
assert.equal(oneBountyOutcomeExitCode('completed','partial'),3);
assert.equal(oneBountyOutcomeExitCode('completed','unknown'),3);
assert.equal(oneBountyOutcomeExitCode('failed','completed'),1);
assert.equal(oneBountyOutcomeExitCode('timed_out','partial'),1);
console.log('One-bounty coverage exit-code regression passed');
