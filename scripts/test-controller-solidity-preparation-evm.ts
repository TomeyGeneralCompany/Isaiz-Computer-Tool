import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const solc=require('./reproduction-runtime/node_modules/solc');
const ganache=require('./reproduction-runtime/node_modules/ganache');
const {runSequence,validateSequence}=require('./reproduction-runtime/solidity-sequence.cjs');
const tokenSource=`pragma solidity ^0.8.20;
contract Token {
 mapping(address=>uint256) public balanceOf;
 function mint(address recipient,uint256 quantity) external {balanceOf[recipient]+=quantity;}
}`;
const vaultSource=`pragma solidity ^0.8.20;
interface IToken {function balanceOf(address) external view returns(uint256);}
contract Vault {
 IToken public token;
 uint256 public recorded;
 constructor(address tokenAddress){token=IToken(tokenAddress);}
 function record(address who) external{recorded=token.balanceOf(who);}
}`;
const compiled=JSON.parse(solc.compile(JSON.stringify({
 language:'Solidity',
 sources:{'Token.sol':{content:tokenSource},'Vault.sol':{content:vaultSource}},
 settings:{outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}
})));
assert.deepEqual((compiled.errors||[]).filter((e:any)=>e.severity==='error'),[]);
const sequence={preparation:{
 deployments:[{id:'token',file:'Token.sol',contract:'Token',constructorArgs:[]}],
 operations:[{id:'mint',deploymentId:'token',function:'mint(address,uint256)',
   args:['$account1','5'],sender:0}],
 checks:[{id:'balance',deploymentId:'token',function:'balanceOf(address)',
   args:['$account1'],sender:0,expect:'5'}]
},constructorArgs:['$deployment:token'],steps:[
 {operation:'send',function:'record(address)',args:['$account1'],sender:0},
 {operation:'call',function:'recorded()',args:[],expect:'5'}
]};
assert.doesNotThrow(()=>validateSequence(sequence));
const transport=()=>ganache.provider({logging:{quiet:true},wallet:{deterministic:true,totalAccounts:3},
 chain:{hardfork:'shanghai',chainId:1337,time:new Date('2020-01-01T00:00:00Z')},
 miner:{blockGasLimit:12000000,timestampIncrement:1}});
const first=await runSequence(compiled.contracts['Vault.sol'].Vault,sequence,transport(),compiled.contracts);
assert.equal(first.steps[0].operation,'setup');
assert.equal(first.steps[1].operation,'setup');
assert.equal(first.steps[3].passed,true);
const second=await runSequence(compiled.contracts['Vault.sol'].Vault,sequence,transport(),compiled.contracts);
assert.deepEqual(first,second,'Fresh EVM replay must reproduce setup and observations');
const failed=structuredClone(sequence);
failed.preparation.checks[0].expect='6';
await assert.rejects(()=>runSequence(compiled.contracts['Vault.sol'].Vault,failed,transport(),compiled.contracts),
 /Preparation check failed: balance/);
const noPrep={constructorArgs:[],steps:[
 {operation:'send',function:'mint(address,uint256)',args:['$account1','3'],sender:0},
 {operation:'call',function:'balanceOf(address)',args:['$account1'],expect:'3'}
]};
assert.doesNotThrow(()=>validateSequence(noPrep));
const old=await runSequence(compiled.contracts['Token.sol'].Token,noPrep,transport());
assert.equal(old.steps[1].passed,true,'Original single-contract sequence stays operational');
console.log('Multi-contract setup and existing single-contract EVM passed');
