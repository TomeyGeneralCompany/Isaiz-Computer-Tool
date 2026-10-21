'use strict';
// Owned synthetic contracts exercise the exact runtime executor without external services.
const assert=require('node:assert/strict');
const solc=require('./reproduction-runtime/node_modules/solc');
const ganache=require('./reproduction-runtime/node_modules/ganache');
const {validateSequence,runSequence}=require('./reproduction-runtime/solidity-sequence.cjs');
const source=`pragma solidity ^0.8.20;
contract Fixture {
 uint256 public value; address public owner;
 constructor(uint256 initial,address admin) payable {value=initial;owner=admin;}
 function set(uint256 x) external {require(msg.sender==owner,"owner");value=x;}
 function set(uint256 x,bool plus) external {value=plus?x+1:x;}
 function deposit() external payable {value+=msg.value;}
 function balance() external view returns(uint256) {return address(this).balance;}
 function pair() external view returns(uint256,bool) {return (value,true);}
}`;
const compiled=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources:{'Fixture.sol':{content:source}},
 settings:{evmVersion:'shanghai',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
assert.equal((compiled.errors||[]).filter(x=>x.severity==='error').length,0);
const artifact=compiled.contracts['Fixture.sol'].Fixture;
const sequence={constructorArgs:['9007199254740993','$account0'],constructorValueWei:'10',steps:[
 {operation:'call',function:'value()',args:[],expect:'9007199254740993'},
 {operation:'call',function:'owner()',args:[],expect:'$account0'},
 {operation:'send',function:'set(uint256)',args:['3'],sender:1,expectRevert:true},
 {operation:'call',function:'value()',args:[],expect:'9007199254740993'},
 {operation:'send',function:'set(uint256)',args:['7']},
 {operation:'send',function:'deposit()',args:[],sender:2,valueWei:'5'},
 {operation:'call',function:'value()',args:[],expect:'12'},
 {operation:'call',function:'balance()',args:[],expect:'15'},
 {operation:'send',function:'set(uint256,bool)',args:['20',true]},
 {operation:'call',function:'pair()',args:[],expect:['21',true]},
]};
async function execute(s) {
 const transport=ganache.provider({logging:{quiet:true},wallet:{deterministic:true,totalAccounts:3},
  chain:{hardfork:'shanghai',chainId:1337,time:new Date('2020-01-01T00:00:00Z')},miner:{blockGasLimit:12000000,timestampIncrement:1}});
 try {return await runSequence(artifact,s,transport);} finally {await transport.disconnect();}
}
(async()=>{
 validateSequence(sequence);
 const first=await execute(sequence);
 assert.ok(first.steps.every(x=>x.passed),JSON.stringify(first));
 assert.equal(first.steps[2].reverted,true);
 assert.deepEqual(await execute(sequence),first,'Fresh deployment replay must be deterministic');
 const mismatch=structuredClone(sequence);mismatch.steps.at(-1).expect=['22',true];
 assert.equal((await execute(mismatch)).steps.at(-1).passed,false);
 const unexpected=structuredClone(sequence);unexpected.steps[2].expectRevert=false;
 await assert.rejects(execute(unexpected),/revert/i);
 const wrongArgs=structuredClone(sequence);wrongArgs.steps[2].args=['not an integer'];
 await assert.rejects(execute(wrongArgs),/invalid|argument/i,'Invalid ABI input cannot masquerade as an expected revert');
 const readAsSend={constructorArgs:['0','$account0'],steps:[{operation:'send',function:'value()',args:[]},sequence.steps[0]]};
 await assert.rejects(execute(readAsSend),/state-changing/);
 for(const invalid of [
  {...sequence,rpcUrl:'https://example.invalid'},
  {...sequence,constructorArgs:[9007199254740992]},
  {...sequence,steps:[]},
  {...sequence,steps:Array(17).fill(sequence.steps[0])},
  {...sequence,steps:[{...sequence.steps[0],sender:3}]},
  {...sequence,steps:[{...sequence.steps[0],function:'value(); arbitrary()'}]},
  {...sequence,constructorValueWei:'-1'},
 ])assert.throws(()=>validateSequence(invalid));
 console.log('Solidity constructors, exact uint256, callers, payable transactions, overloads, expected/unexpected reverts, read assertions and deterministic replay: PASSED');
})().catch(e=>{console.error(e);process.exitCode=1;});
