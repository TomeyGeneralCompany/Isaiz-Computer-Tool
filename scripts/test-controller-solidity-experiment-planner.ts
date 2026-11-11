import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {constructSolidityExperiments} from '../packages/security-solver/src/controller-solidity-experiment-planner';
const content=`pragma solidity ^0.8.20;
contract Vault {
  address public owner;
  uint256 public reserve;
  constructor() { owner = msg.sender; }
  function setReserve(uint256 value) external {
    require(msg.sender == owner, "owner only");
    reserve = value;
  }
}`;
const input={
 repositoryCommit:'f'.repeat(40),targetPath:'contracts/Vault.sol',
 targetSelector:'Vault.setReserve',
 sources:[{path:'contracts/Vault.sol',sha256:createHash('sha256').update(content).digest('hex'),content}],
 declarations:[
 {selector:'Vault.setReserve',operation:'send' as const,inputs:['uint256']},
 {selector:'Vault.reserve',operation:'call' as const,inputs:[]},
 {selector:'Vault.owner',operation:'call' as const,inputs:[]}
 ]};
const a=constructSolidityExperiments(input);
assert.equal(a.ok,true,JSON.stringify(a));
if(a.ok){
 assert.ok(a.experiments.length>0);
 assert.ok(a.experiments.every(x=>x.sequence.steps.length===6));
 assert.deepEqual(a,constructSolidityExperiments(input),'Construction must be deterministic');
}
const changed={...input,sources:[{...input.sources[0],content:content+'\n'}]};
assert.deepEqual(constructSolidityExperiments(changed).ok,false,'Source hash must match bytes');
const unguarded={...input,sources:[{...input.sources[0],
 content:content.replace('require(msg.sender == owner, "owner only");','')}]};
unguarded.sources[0].sha256=createHash('sha256').update(unguarded.sources[0].content).digest('hex');
assert.equal(constructSolidityExperiments(unguarded).ok,false,'No authorization proof, no scenario');
console.log('Standalone experiment construction passed');
