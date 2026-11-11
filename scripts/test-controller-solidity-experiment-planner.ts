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

// Regression derived from the 88mphV3 run's actual Vesting02 / BoringOwnable
// initialization, owner guard and MPHMinter setter. Standalone; no reader.
const ownable='pragma solidity 0.8.4; contract BoringOwnable {'+
  'address private _owner;'+
  'function __Ownable_init() internal { _owner = msg.sender; }'+
  'function owner() external view returns(address){return _owner;}'+
  'modifier onlyOwner(){require(msg.sender == _owner, "Ownable: caller is not the owner");_;}'+
  '}';
const vesting='pragma solidity 0.8.4; import {BoringOwnable} from "../libs/BoringOwnable.sol";'+
  'interface IERC20 {} interface MPHMinter {} contract Vesting02 is BoringOwnable {'+
  'IERC20 public token; MPHMinter public mphMinter;'+
  'function initialize(address _token,string calldata tokenName,string calldata tokenSymbol) external initializer {'+
  '__Ownable_init(); __ERC721_init(tokenName, tokenSymbol); token = IERC20(_token); }'+
  'function setMPHMinter(address newValue) external onlyOwner {'+
  'require(newValue != address(0),"Vesting02: 0 address");'+
  'mphMinter = MPHMinter(newValue); emit ESetMPHMinter(newValue); }'+
  'event ESetMPHMinter(address newValue); }';
const vestingInput={
 repositoryCommit:'f'.repeat(40),
 targetPath:'contracts/rewards/Vesting02.sol',
 targetSelector:'Vesting02.setMPHMinter',
 sources:[
  {path:'contracts/rewards/Vesting02.sol',sha256:createHash('sha256').update(vesting).digest('hex'),content:vesting},
  {path:'contracts/libs/BoringOwnable.sol',sha256:createHash('sha256').update(ownable).digest('hex'),content:ownable}
 ],
 declarations:[{selector:'Vesting02.setMPHMinter',operation:'send' as const,inputs:['address']}]
};
const inheritedResult=constructSolidityExperiments(vestingInput);
assert.equal(inheritedResult.ok,true,JSON.stringify(inheritedResult));
if(inheritedResult.ok) {
 assert.equal(inheritedResult.experiments.length,1);
 assert.equal(inheritedResult.experiments[0].sequence.steps.length,7);
 assert.equal(inheritedResult.experiments[0].witnesses.length,6);
}

console.log('Standalone experiment construction passed');
