import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {sourceGroundedOwnerGuardProbes} from '../packages/security-solver/src/controller-solidity-owner-scenarios';
import {soliditySequenceSchema} from '../packages/security-solver/src/solidity-sequence';

const root='scripts/fixtures/real-world-88mph-v3/';
const source=readFileSync(root+'contracts/DInterest.sol','utf8');
const owner=readFileSync(root+'contracts/libs/BoringOwnable.sol','utf8');
assert.match(source,/pragma solidity 0\.8\.4;/);
const menu=[
  {selector:'DInterest.initialize',operation:'send' as const,
    inputs:['uint64','uint256','address','address','address','address','address','address']},
  {selector:'DInterest.GlobalDepositCap',operation:'call' as const,inputs:[]},
  {selector:'DInterest.setGlobalDepositCap',operation:'send' as const,inputs:['uint256']},
  {selector:'DInterest.MinDepositAmount',operation:'call' as const,inputs:[]},
  {selector:'DInterest.setMinDepositAmount',operation:'send' as const,inputs:['uint256']}
];
const context={path:'source-1/contracts/DInterest.sol',
  peers:[{path:'source-1/contracts/libs/BoringOwnable.sol',source:owner}]};
const plans=sourceGroundedOwnerGuardProbes(source,menu,context);
const cap=plans.find(p=>p.selector==='DInterest.setGlobalDepositCap');
assert.ok(cap,'Actual 88mph v3 source must yield a guarded finance-state experiment');
soliditySequenceSchema.parse(cap.probe.sequence);
assert.equal(cap.probe.sequence.steps.length,7);
assert.deepEqual(cap.probe.sequence.steps.filter(s=>s.operation==='send').map(s=>s.sender),[0,1,0]);
assert.equal((cap.probe.sequence.steps.filter(s=>s.operation==='send')[1] as any).expectRevert,true);
assert.equal(cap.probe.sequence.steps.at(-1)?.operation,'call');
assert.equal((cap.probe.sequence.steps.at(-1) as any).expect,'2');
assert.ok(!plans.some(p=>p.selector==='DInterest.setMinDepositAmount'),
  'An initializer-assigned baseline cannot be invented as zero');
assert.equal(sourceGroundedOwnerGuardProbes(source,menu,{
  ...context,peers:[{...context.peers[0],source:owner.replace('msg.sender == _owner','msg.sender != _owner')}]
}).length,0,'A changed authorization guard invalidates the source proof');
assert.equal(sourceGroundedOwnerGuardProbes(source.replace('__Ownable_init();',''),menu,context).length,0,
  'Missing source-proven owner initialization invalidates the scenario');
console.log('88mph v3 source-grounded owner finance scenarios passed');
