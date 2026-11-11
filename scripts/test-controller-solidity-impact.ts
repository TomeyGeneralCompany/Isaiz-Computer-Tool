import assert from 'node:assert/strict';
import {generateCrucible} from './lotus-crucible-generator';
import {roleConsumerImpactSequence,roleConsumerImpactObserved,inheritedRoleConsumerImpactSequence,inheritedRoleConsumerImpactObserved} from '../packages/security-solver/src/controller-solidity-consumer-impact';
import {soliditySequenceSchema} from '../packages/security-solver/src/solidity-sequence';
import {sourceGroundedSolidityProbes} from '../packages/security-solver/src/controller-solidity-security-probes';
import {controllerVerifiedLocalSolidityConsumerReview} from '../packages/security-solver/src/controller-review-boundary';
const trial=generateCrucible({language:'solidity',seed:'verified-consumer-impact-20261106'});
const sink=trial.privateAnswerKey.defects[0].affectedPaths.at(-1)!;
const source=trial.files[sink];
const sequence=roleConsumerImpactSequence(source,'operator','rotateOperator');
assert.ok(sequence,'A source-declared settlement consumer must yield an impact sequence');
assert.ok(soliditySequenceSchema.safeParse(sequence).success);
assert.equal(sequence.steps.length,8);
const accounts=['0x'+'11'.repeat(20),'0x'+'22'.repeat(20),'0x'+'33'.repeat(20)];
const observations={accounts,steps:[
 {operation:'call',function:'operator()',actual:accounts[0],passed:true},
 {operation:'send',function:'fund(uint256)',sender:0,passed:true,reverted:false},
 {operation:'send',function:'settle(address,uint256)',sender:2,passed:true,reverted:true},
 {operation:'call',function:'credit(address)',actual:'0',passed:true},
 {operation:'send',function:'rotateOperator(address)',sender:1,passed:true,reverted:false},
 {operation:'call',function:'operator()',actual:accounts[2],passed:true},
 {operation:'send',function:'settle(address,uint256)',sender:2,passed:true,reverted:false},
 {operation:'call',function:'credit(address)',actual:'1',passed:true}
]};
assert.ok(roleConsumerImpactObserved(observations,'operator','rotateOperator'));
const selector=sink.split('/').at(-1)!.replace(/\.sol$/,'')+'.rotateOperator';
const reviewed=controllerVerifiedLocalSolidityConsumerReview({
 source,selector,sequence,replay:{
  status:'behavior_observed',kind:'solidity_sequence',
  behavior_observed:true,observations
 }
});
assert.equal(reviewed?.verdict,'approve','Independent replay plus protected-consumer proof supports local technical approval');
assert.equal(reviewed?.recommendation,'dont_submit','Offline technical proof must not enable bounty submission');
assert.equal(controllerVerifiedLocalSolidityConsumerReview({
 source,selector,sequence,replay:{
  status:'observation_only',kind:'solidity_sequence',
  behavior_observed:false,observations
 }
}),null,'An unverified role assertion cannot be approved');

for(const patch of [
 {index:2,field:'reverted',value:false},
 {index:4,field:'passed',value:false},
 {index:5,field:'actual',value:accounts[0]},
 {index:6,field:'reverted',value:true},
 {index:7,field:'actual',value:'0'},
 {index:0,field:'passed',value:false},
 {index:3,field:'passed',value:false},
 {index:5,field:'passed',value:false},
 {index:7,field:'passed',value:false}
]){
 const changed=structuredClone(observations);
 (changed.steps[patch.index] as Record<string,unknown>)[patch.field]=patch.value;
 assert.equal(roleConsumerImpactObserved(changed,'operator','rotateOperator'),false,
   'Missing protected-consumer evidence must not be elevated to a finding');
}
const secured=source.replace('require(nextOperator!=address(0),"zero operator");',
  'require(msg.sender==administrator,"administrator");');
assert.ok(roleConsumerImpactSequence(secured,'operator','rotateOperator'),
 'Controller can attempt the same counterfactual on a guarded setter; the actual EVM must reject it.');
const noConsumer=source.replace('require(msg.sender==operator,"operator only");','require(msg.sender==administrator,"admin only");');
assert.equal(roleConsumerImpactSequence(noConsumer,'operator','rotateOperator'),null,
 'The controller must not infer impact where the allegedly protected consumer uses a different authority');
const baseFile='contracts/settlement/SettlementAuthority.sol';
const derivedFile='contracts/settlement/SettlementVault.sol';
const baseSource='pragma solidity ^0.8.20; contract SettlementAuthority { address public operator; constructor(){operator=msg.sender;} function rotateOperator(address next) external {operator=next;} }';
const derivedSource='pragma solidity ^0.8.20; import "./SettlementAuthority.sol"; contract SettlementVault is SettlementAuthority { mapping(address=>uint256) public credit; uint256 public totalCredit; function fund(address recipient,uint256 amount) external {uint256 v=amount.bounded(type(uint128).max);credit[recipient]+=v;totalCredit+=v;} function settle(address recipient,uint256 amount) external {require(msg.sender==operator,"operator only");require(amount>0&&amount<=totalCredit,"bad amount");credit[recipient]+=amount;totalCredit-=amount;} }';
const inherited=inheritedRoleConsumerImpactSequence(baseSource,derivedSource,'operator','rotateOperator',baseFile,derivedFile,'SettlementVault');
assert.ok(inherited,'Inherited source-linked settlement consumer must yield an executable impact sequence');
assert.ok(soliditySequenceSchema.safeParse(inherited).success);
assert.equal(inherited.steps.length,10);
assert.equal(inherited.deployment?.file,derivedFile);
const grounded=sourceGroundedSolidityProbes(baseSource,[
  {selector:'SettlementAuthority.operator',operation:'call',inputs:[]},
  {selector:'SettlementAuthority.rotateOperator',operation:'send',inputs:['address']}
],{path:'source-1/'+baseFile,peers:[
  {path:'source-1/'+baseFile,source:baseSource},
  {path:'source-1/'+derivedFile,source:derivedSource}
]});
assert.equal(grounded.length,1,'Source-grounded controller must select inherited consumer experiment');
assert.deepEqual(grounded[0].probe.sequence,inherited,
 'Controller must use actual inherited-consumer transactions, not only a role getter');
assert.equal(inheritedRoleConsumerImpactSequence(baseSource,derivedSource.replace('is SettlementAuthority','is Other'), 'operator','rotateOperator',baseFile,derivedFile,'SettlementVault'),null);
assert.equal(inheritedRoleConsumerImpactSequence(baseSource,derivedSource.replace('msg.sender==operator','msg.sender==administrator'), 'operator','rotateOperator',baseFile,derivedFile,'SettlementVault'),null);
assert.equal(inheritedRoleConsumerImpactObserved({accounts,steps:[]},'operator','rotateOperator'),false);
console.log('Controller role mutation to protected-consumer impact, negative evidence and source scope PASSED');
