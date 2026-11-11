import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {generateCrucible} from './lotus-crucible-generator';
import {roleConsumerImpactSequence,roleConsumerImpactObserved,inheritedRoleConsumerImpactSequence,inheritedRoleConsumerImpactObserved} from '../packages/security-solver/src/controller-solidity-consumer-impact';
const require=createRequire(import.meta.url);
const solc=require('./reproduction-runtime/node_modules/solc');
const ganache=require('./reproduction-runtime/node_modules/ganache');
const {runSequence}=require('./reproduction-runtime/solidity-sequence.cjs');
const trial=generateCrucible({language:'solidity',seed:'consumer-impact-evm-20261106'});
const target=trial.privateAnswerKey.defects[0].affectedPaths.at(-1)!;
const source=trial.files[target];
const contractName=target.split('/').at(-1)!.replace(/\.sol$/,'');
const sequence=roleConsumerImpactSequence(source,'operator','rotateOperator');
assert.ok(sequence);
const compile=JSON.parse(solc.compile(JSON.stringify({
 language:'Solidity',
 sources:{
  [target]:{content:source},
  'contracts/interfaces/ICrucibleRoute.sol':{content:trial.files['contracts/interfaces/ICrucibleRoute.sol']}
 },
 settings:{evmVersion:'shanghai',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}
})));
assert.deepEqual((compile.errors||[]).filter((e:any)=>e.severity==='error'),[]);
const artifact=compile.contracts[target][contractName];
const run=async(seq:unknown)=>{
 const provider=ganache.provider({logging:{quiet:true},wallet:{deterministic:true,totalAccounts:3},
  chain:{hardfork:'shanghai',chainId:1337,time:new Date('2020-01-01T00:00:00Z')},
  miner:{blockGasLimit:12000000,timestampIncrement:1}});
 try{return await runSequence(artifact,seq,provider);}finally{await provider.disconnect();}
};
const first=await run(sequence);
assert.equal(first.steps[0].operation,'call');
assert.equal(first.steps[0].passed,true,'Initial role assertion must pass');
assert.equal(first.steps[3].passed,true,'Initial beneficiary balance assertion must pass');
assert.equal(first.steps[5].passed,true,'Post-mutation role assertion must pass');
assert.equal(first.steps[7].passed,true,'Final beneficiary balance assertion must pass');
assert.equal(first.steps[2].reverted,true,'Unauthorised consumer must initially be blocked');
assert.equal(first.steps[4].reverted,false,'Role setter must be executable by nonadministrator');
assert.equal(first.steps[6].reverted,false,'Consumer must become executable after role transfer');
assert.ok(roleConsumerImpactObserved(first,'operator','rotateOperator'));
assert.deepEqual(await run(sequence),first,'Independent deterministic replay must match actual EVM receipts and credit change');
const guarded=structuredClone(sequence);
guarded.steps[4]={...guarded.steps[4],expectRevert:true};
const guardSource=source.replace('require(nextOperator!=address(0),"zero operator");',
 'require(msg.sender==administrator,"admin only");');
const secured=JSON.parse(solc.compile(JSON.stringify({
 language:'Solidity',sources:{
 [target]:{content:guardSource},
 'contracts/interfaces/ICrucibleRoute.sol':{content:trial.files['contracts/interfaces/ICrucibleRoute.sol']}
 },
 settings:{evmVersion:'shanghai',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}
})));
assert.deepEqual((secured.errors||[]).filter((e:any)=>e.severity==='error'),[]);
const securedArtifact=secured.contracts[target][contractName];
const provider=ganache.provider({logging:{quiet:true},wallet:{deterministic:true,totalAccounts:3},
 chain:{hardfork:'shanghai',chainId:1337,time:new Date('2020-01-01T00:00:00Z')},
 miner:{blockGasLimit:12000000,timestampIncrement:1}});
try{
 const securedEvidence=await runSequence(securedArtifact,sequence,provider);
 assert.equal(securedEvidence.steps[4].reverted,true);
 assert.equal(securedEvidence.steps[4].passed,false);
 assert.equal(roleConsumerImpactObserved(securedEvidence,'operator','rotateOperator'),false,
  'Authorized setter must not pass vulnerable mutation sequence');
}finally{await provider.disconnect();}
// The inherited settlement consumer must run on the derived deployment;
// probing the standalone authority cannot prove downstream credit impact.
const baseFile='contracts/settlement/SettlementAuthority.sol';
const derivedFile='contracts/settlement/SettlementVault.sol';
const baseSource='pragma solidity ^0.8.20; contract SettlementAuthority { address public operator; constructor(){operator=msg.sender;} function rotateOperator(address next) external {require(next!=address(0),"zero");operator=next;} }';
const derivedSource='pragma solidity ^0.8.20; import "./SettlementAuthority.sol"; contract SettlementVault is SettlementAuthority { mapping(address=>uint256) public credit; uint256 public totalCredit; function fund(address recipient,uint256 amount) external {credit[recipient]+=amount;totalCredit+=amount;} function settle(address recipient,uint256 amount) external {require(msg.sender==operator,"operator only");require(amount>0&&amount<=totalCredit,"bad amount");credit[recipient]+=amount;totalCredit-=amount;} }';
const derivedSequence=inheritedRoleConsumerImpactSequence(baseSource,derivedSource,'operator','rotateOperator',baseFile,derivedFile,'SettlementVault');
assert.ok(derivedSequence);
const derivedCompile=JSON.parse(solc.compile(JSON.stringify({
 language:'Solidity',sources:{[baseFile]:{content:baseSource},[derivedFile]:{content:derivedSource}},
 settings:{evmVersion:'shanghai',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}
})));
assert.deepEqual((derivedCompile.errors||[]).filter((e:any)=>e.severity==='error'),[]);
const derivedArtifact=derivedCompile.contracts[derivedFile].SettlementVault;
const derivedProvider=ganache.provider({logging:{quiet:true},wallet:{deterministic:true,totalAccounts:3},
 chain:{hardfork:'shanghai',chainId:1337,time:new Date('2020-01-01T00:00:00Z')},
 miner:{blockGasLimit:12000000,timestampIncrement:1}});
try{
 const observed=await runSequence(derivedArtifact,derivedSequence,derivedProvider);
 assert.ok(inheritedRoleConsumerImpactObserved(observed,'operator','rotateOperator'));
 const tampered=structuredClone(observed);
 tampered.steps[7].reverted=true;
 assert.equal(inheritedRoleConsumerImpactObserved(tampered,'operator','rotateOperator'),false);
}finally{await derivedProvider.disconnect();}
console.log('Solidity independent EVM denied-before/allowed-after protected consumer impact and secure-control rejection PASSED');
