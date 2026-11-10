import assert from 'node:assert/strict';
import { AuditAllowance } from '../packages/security-solver/src/audit-allowance';
import { sourcePriority } from '../packages/security-solver/src/source-capability';
const a=new AuditAllowance(80,0,100000,true);
for(let i=61;i<=75;i++)a.read('file',i*100,(i+1)*100,i);
assert.equal(a.read('file',6100,6200,75),false);
assert.equal(a.read('file',6150,6250,75),false);
assert.ok(a.extend(75,50000));assert.equal(a.turns,120);assert.equal(a.deadline,3700000);
assert.equal(a.extend(115,60000),null,'Old credits cannot fund another extension');
const unchanged=new AuditAllowance(80,0,100000,true);
for(let i=60;i<80;i++)unchanged.read('same',0,100,i);
assert.equal(unchanged.extend(79,99999),null);
const timed=new AuditAllowance(80,0,100000,true);
for(let i=1;i<=10;i++)timed.read('file',i*100,(i+1)*100,i);
assert.ok(timed.extend(10,90000),'Time pressure also extends both budgets');
const expired=new AuditAllowance(80,0,100000,true);
for(let i=61;i<=75;i++)expired.read('file',i*100,(i+1)*100,i);
assert.equal(expired.extend(75,100001),null);
const fixed=new AuditAllowance(80,0,100000);
for(let i=61;i<=75;i++)fixed.read('file',i*100,(i+1)*100,i);
assert.equal(fixed.extend(75,90000),null);

// Production investigations have no cumulative turn or wall-clock ceiling.
// Evidence-backed extensions remain possible beyond the former 640-turn cap.
const unbounded=new AuditAllowance(80,0,100000,true,640,true);
for(let i=621;i<=639;i++)unbounded.read('late-file',i*100,(i+1)*100,i);
unbounded.turns=640;
assert.ok(unbounded.extend(639,90000),'Productive work beyond turn 640 must extend');
assert.equal(unbounded.turns,680);
assert.equal(unbounded.snapshot().hardTurns,null);
assert.equal(unbounded.snapshot().unbounded,true);
assert.ok(sourcePriority('contracts/Vault.sol')>sourcePriority('.solcover.js'));
assert.ok(sourcePriority('src/Vault.sol')>sourcePriority('vendors/foo/tests/x.js'));
console.log('Progress extensions, repeated/overlapping reads, expiry and source priority PASSED');
