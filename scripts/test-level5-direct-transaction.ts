import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {transactionEntryLine,callerLineReferences} from '../packages/security-solver/src/source-function-reference';

// Regression for the owned Level 5 Solidity declaration-as-caller loop.
// The source declaration is a valid direct-transaction entry only when a
// recorded send exists; it must never be accepted as a caller invocation.
const source=`contract SettlementAuthority {
  address public operator;
  function rotateOperator(address next) external {
    operator = next;
  }
}`;
assert.equal(transactionEntryLine(source,3,'SettlementAuthority.rotateOperator'),true);
assert.equal(callerLineReferences(source,3,'SettlementAuthority.rotateOperator'),false);
const flow=readFileSync('packages/security-solver/src/local-program-flow.ts','utf8');
assert.match(flow,/record\.spec\.kind==='solidity_sequence'/);
assert.match(flow,/step\.operation==='send'/);
assert.match(flow,/declarations\.length===1/);
assert.match(flow,/reads\.sawLine\(sourcePath,sourceText,index\+1\)/);
assert.match(flow,/candidate\.reachability='direct_transaction'/);
assert.match(flow,/if\(!validReachability\(finding,record,callerRelative\.split\(sep\)\.join\("\/"\),text\)\)/);
const grade=readFileSync('scripts/lotus-gauntlet.ts','utf8');
assert.match(grade,/resultStatus:milestones\.verifiedFinding\?/);
console.log('Owned Solidity direct-transaction evidence reconciliation PASSED');
