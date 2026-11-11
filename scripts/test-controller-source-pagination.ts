import assert from 'node:assert/strict';
import {deliveredSourcePageComplete} from '../packages/security-solver/src/controller-source-pagination';

// Reproduces the 2026-11-11 88mph laptop run: DInterest.sol has 59,255
// characters, but the last context-fitted read ended at 59,092. The raw
// page's EOF must not cause the controller to claim complete coverage.
const raw={end:59255,totalCharacters:59255,nextOffset:null};
const fitted={end:59092,totalCharacters:59255,nextOffset:59092};
assert.equal(deliveredSourcePageComplete(raw),true);
assert.equal(deliveredSourcePageComplete(fitted),false);
assert.equal(deliveredSourcePageComplete({...fitted,nextOffset:null}),false);
assert.equal(deliveredSourcePageComplete({end:59255,totalCharacters:59255,nextOffset:59255}),false);
assert.equal(deliveredSourcePageComplete({end:59255,totalCharacters:59255,nextOffset:null}),true);
console.log('Delivered source EOF regression passed');
