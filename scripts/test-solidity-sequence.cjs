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
 const unexpectedResult=await execute(unexpected);
 assert.equal(unexpectedResult.steps[2].reverted,true);
 assert.equal(unexpectedResult.steps[2].passed,false);
 assert.match(unexpectedResult.steps[2].gasUsed,/^[0-9]+$/);
 assert.equal(unexpectedResult.steps[3].passed,true,
   'Read after an unexpected mined revert must remain observable');
 // ERC-1155-like setup: a transfer without minted balance must revert,
 // but the failed transfer and unchanged balance are both recorded.
 const tokenSource=`pragma solidity ^0.8.20;
 contract TokenFixture {
   mapping(address => uint256) public balanceOf;
   function mint(address to,uint256 amount) external {balanceOf[to]+=amount;}
   function safeTransferFrom(address from,address to,uint256 amount) external {
     require(msg.sender==from,"unauthorized");
     require(balanceOf[from]>=amount,"insufficient balance");
     balanceOf[from]-=amount;balanceOf[to]+=amount;
   }
 }`;
 const tokenCompiled=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',
   sources:{'TokenFixture.sol':{content:tokenSource}},settings:{evmVersion:'shanghai',
   outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
 const tokenArtifact=tokenCompiled.contracts['TokenFixture.sol'].TokenFixture;
 const tokenTransport=ganache.provider({logging:{quiet:true},wallet:{deterministic:true,totalAccounts:3},
   chain:{hardfork:'shanghai'},miner:{blockGasLimit:12000000}});
 try {
   const tokenResult=await runSequence(tokenArtifact,{constructorArgs:[],steps:[
     {operation:'observe',function:'balanceOf(address)',args:['$account0']},
     {operation:'send',function:'safeTransferFrom(address,address,uint256)',
       args:['$account0','$account1','1'],expectRevert:false},
     {operation:'observe',function:'balanceOf(address)',args:['$account0']},
     {operation:'send',function:'mint(address,uint256)',args:['$account0','2']},
     {operation:'send',function:'safeTransferFrom(address,address,uint256)',
       args:['$account0','$account1','1']},
     {operation:'call',function:'balanceOf(address)',args:['$account1'],expect:'1'}
   ]},tokenTransport);
   assert.equal(tokenResult.steps[1].reverted,true);
   assert.equal(tokenResult.steps[1].passed,false);
   assert.equal(tokenResult.steps[2].actual,'0');
   assert.equal(tokenResult.steps[4].reverted,false);
   assert.equal(tokenResult.steps[5].passed,true);
 } finally {await tokenTransport.disconnect();}
 // Regression: controller-produced source-derived state observation, rather
 // than an unrelated gated view function, runs in the real local EVM.
 const authoritySource=`pragma solidity ^0.8.20;
 contract Authority {
   address public administrator;
   address public operator;
   constructor(){administrator=msg.sender;operator=msg.sender;}
   function rotateOperator(address next) external {operator=next;}
   function changeAdministrator(address next) external {
     require(msg.sender==administrator,"only admin");administrator=next;
   }
 }`;
 const authorityCompiled=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',
   sources:{'Authority.sol':{content:authoritySource}},settings:{evmVersion:'shanghai',
   outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
 assert.equal((authorityCompiled.errors||[]).filter(x=>x.severity==='error').length,0);
 const authority=authorityCompiled.contracts['Authority.sol'].Authority;
 const authoritySequence={constructorArgs:[],steps:[
   {operation:'observe',function:'operator()',args:[]},
   {operation:'send',function:'rotateOperator(address)',args:['$account1'],sender:1,expectRevert:true},
   {operation:'observe',function:'operator()',args:[]}
 ]};
 const providerForAuthority=()=>ganache.provider({logging:{quiet:true},
   wallet:{deterministic:true,totalAccounts:3},chain:{hardfork:'shanghai',chainId:1337,
   time:new Date('2020-01-01T00:00:00Z')},
   miner:{blockGasLimit:12000000,timestampIncrement:1}});
 const authorityTransport=providerForAuthority();
 try {
   const output=await runSequence(authority,authoritySequence,authorityTransport);
   assert.equal(output.steps[1].reverted,false);
   assert.equal(output.steps[1].passed,false,'Actual non-admin success disproves the expected revert');
   assert.equal(output.steps[2].actual,output.accounts[1]);
   assert.notEqual(output.steps[0].actual,output.steps[2].actual);
 } finally {await authorityTransport.disconnect();}
 // Controller preparation must mine and record balance/approval setup before
 // the actual transfer, without treating setup as vulnerability evidence.
 const harnessSource=`pragma solidity ^0.8.20;
 contract TomeyERC1155ProbeHarness {
   mapping(uint256=>mapping(address=>uint256)) private balances;
   mapping(address=>mapping(address=>bool)) private approvals;
   function balanceOf(address a,uint256 id) external view returns(uint256){return balances[id][a];}
   function isApprovedForAll(address a,address b) external view returns(bool){return approvals[a][b];}
   function setApprovalForAll(address b,bool approved) external {approvals[msg.sender][b]=approved;}
   function tomeyMintBatch(address a,uint256[] memory ids,uint256[] memory amounts) external {
     for(uint i=0;i<ids.length;i++)balances[ids[i]][a]+=amounts[i];
   }
   function tomeyMint(address a,uint256 id,uint256 amount) external {balances[id][a]+=amount;}
   function safeTransferFrom(address a,address b,uint256 id,uint256 amount,bytes memory) external {
     require(msg.sender==a||approvals[a][msg.sender],"approval");
     require(balances[id][a]>=amount,"balance");
     balances[id][a]-=amount;balances[id][b]+=amount;
   }
 }`;
 const hc=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',
   sources:{'Harness.sol':{content:harnessSource}},
   settings:{evmVersion:'shanghai',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
 assert.deepEqual((hc.errors||[]).filter(e=>e.severity==='error'),[]);
 const ha=hc.contracts['Harness.sol'].TomeyERC1155ProbeHarness;
 const ht=ganache.provider({logging:{quiet:true},wallet:{deterministic:true,totalAccounts:3},
   chain:{hardfork:'shanghai'},miner:{blockGasLimit:12000000}});
 try{
   const h=await runSequence(ha,{constructorArgs:[],steps:[
     {operation:'send',function:'safeTransferFrom(address,address,uint256,uint256,bytes)',
       args:['$account0','$account2','1','3','0x'],sender:1},
     {operation:'call',function:'balanceOf(address,uint256)',args:['$account2','1'],expect:'3'}
   ]},ht);
   assert.equal(h.steps[0].operation,'setup');
   assert.equal(h.steps[1].operation,'setup');
   assert.equal(h.steps[2].operation,'send');
   assert.equal(h.steps[2].reverted,false);
   assert.equal(h.steps[3].passed,true);
 }finally{await ht.disconnect();}
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
