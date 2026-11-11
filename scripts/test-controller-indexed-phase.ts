import assert from 'node:assert/strict';
import {indexedPhaseStatus} from '../packages/security-solver/src/controller-indexed-phase';

// Every language has the same mandatory full-read-to-experiment boundary.
const paths=['source-1/contracts/Vault.sol','source-1/src/Bank.java',
  'source-1/services/payment.py','source-1/lib/router.js'];
const first=indexedPhaseStatus(paths,[paths[0],paths[1],paths[2]]);
assert.deepEqual(first,{eligible:4,completed:3,remaining:[paths[3]],ready:false});
const complete=indexedPhaseStatus(paths,paths);
assert.equal(complete.ready,true);
assert.equal(complete.completed,4);
const none=indexedPhaseStatus([],[]);
assert.equal(none.ready,false);
assert.equal(none.eligible,0);
// Non-source config files never satisfy or enlarge the investigation queue.
const mixed=indexedPhaseStatus([...paths,'README.md','source-1/package.json'],paths);
assert.equal(mixed.ready,true);
assert.equal(mixed.eligible,4);
// A first-page visit does not count as a terminal page.
assert.equal(indexedPhaseStatus(paths,[paths[0]]).completed,1);
console.log('PASS: four-language indexed reading phase gate');
