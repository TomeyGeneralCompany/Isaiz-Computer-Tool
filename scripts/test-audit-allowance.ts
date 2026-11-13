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
for(let i=661;i<=679;i++)unbounded.read('second-file',i*100,(i+1)*100,i);
assert.ok(unbounded.extend(679,36_000_000),
  'Real source progress must extend an unbounded hunt beyond the former ten-hour cutoff');
assert.equal(unbounded.turns,720);
const idleUnbounded=new AuditAllowance(80,0,100000,true,640,true);
assert.equal(idleUnbounded.extend(79,36_000_000),null,
  'No new source or probe evidence must never buy extra turns');
const slowUnbounded=new AuditAllowance(80,0,100000,true,640,true);
slowUnbounded.read('one-genuine-file',0,100,79);
assert.ok(slowUnbounded.extend(79,96*60*60*1000),
  'A single novel, recent source read must extend productive work even after 96 hours');
assert.equal(slowUnbounded.turns,120);
const repetitive=new AuditAllowance(80,0,100000,true,640,true);
repetitive.read('same-file',0,100,60);
for(let turn=61;turn<=79;turn++)repetitive.read('same-file',0,100,turn);
assert.equal(repetitive.extend(79,96*60*60*1000),null,
  'Re-reading the same range is not progress and must not extend work');
assert.ok(sourcePriority('contracts/Vault.sol')>sourcePriority('.solcover.js'));
assert.ok(sourcePriority('src/Vault.sol')>sourcePriority('vendors/foo/tests/x.js'));
console.log('Progress extensions, repeated/overlapping reads, expiry and source priority PASSED');
