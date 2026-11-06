import assert from 'node:assert/strict';
import {generateCrucible} from './lotus-crucible-generator';
import {roleConsumerImpactSequence,roleConsumerImpactObserved} from '../packages/security-solver/src/controller-solidity-consumer-impact';
import {soliditySequenceSchema} from '../packages/security-solver/src/solidity-sequence';
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
 {operation:'observe',function:'operator()',actual:accounts[0]},
 {operation:'send',function:'fund(uint256)',sender:0,passed:true,reverted:false},
 {operation:'send',function:'settle(address,uint256)',sender:2,passed:true,reverted:true},
 {operation:'observe',function:'credit(address)',actual:'0'},
 {operation:'send',function:'rotateOperator(address)',sender:1,passed:true,reverted:false},
 {operation:'observe',function:'operator()',actual:accounts[2]},
 {operation:'send',function:'settle(address,uint256)',sender:2,passed:true,reverted:false},
 {operation:'observe',function:'credit(address)',actual:'1'}
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
 {index:7,field:'actual',value:'0'}
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
console.log('Controller role mutation to protected-consumer impact, negative evidence and source scope PASSED');
