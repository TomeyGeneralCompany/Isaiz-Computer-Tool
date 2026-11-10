import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {SoliditySourceIndex} from '../packages/security-solver/src/solidity-source-index';
import {buildBaselineSequence} from '../packages/security-solver/src/solidity-probe-inputs';
import {solidityDependentSources} from '../packages/security-solver/src/source-flow-facts';
import {generate} from './lotus-gauntlet-fixtures';
const root=await mkdtemp(join(tmpdir(),'lotus-solidity-owned-menu-'));
try {
 const fixture=generate('solidity',144);
 for(const [path,code] of Object.entries(fixture.files)){
   const full=join(root,path);await mkdir(dirname(full),{recursive:true});
   await writeFile(full,code);
 }
 const index=new SoliditySourceIndex(root);
 const authority=await index.probeMenu(join(root,'contracts/settlement/SettlementAuthority.sol'));
 assert.ok(authority.some(item=>item.selector==='SettlementAuthority.operator' && item.operation==='call'),
   'Public state variable must appear as an executable ABI getter');
 assert.ok(authority.some(item=>item.selector==='SettlementAuthority.administrator' && item.operation==='call'));
 const sequence=buildBaselineSequence(authority,'SettlementAuthority.rotateOperator',true);
 assert.ok(sequence,'Controller must construct an executable sequence from the selected source');
 assert.equal((sequence?.steps[1] as any)?.sender,1);
 assert.equal((sequence?.steps[1] as any)?.args?.[0],'$account2',
   'Role-mutation probe must use a distinct target account, not the nonadmin sender');
 assert.equal((sequence?.steps[1] as any)?.expectRevert,undefined,
   'Reproduction observes actual authorization behavior rather than prescribing a revert');
 assert.deepEqual(sequence?.steps.map(step=>step.function),[
   'operator()','rotateOperator(address)','operator()'
 ],'Controller should observe the state actually modified by the selected function');
 // Mirror the real 88mph ERC1155 probe menu: the controller must transfer
 // positive balances to a distinct recipient and observe that recipient.
 const erc1155Menu=[
   {selector:'ERC1155Upgradeable.safeTransferFrom',operation:'send' as const,
     inputs:['address','address','uint256','uint256','bytes']},
   {selector:'ERC1155Upgradeable.safeBatchTransferFrom',operation:'send' as const,
     inputs:['address','address','uint256[]','uint256[]','bytes']},
   {selector:'ERC1155Upgradeable.setApprovalForAll',operation:'send' as const,
     inputs:['address','bool']},
   {selector:'ERC1155Upgradeable.balanceOf',operation:'call' as const,
     inputs:['address','uint256']},
   {selector:'ERC1155Upgradeable.isApprovedForAll',operation:'call' as const,
     inputs:['address','address']},
 ];
 const single=buildBaselineSequence(erc1155Menu,'ERC1155Upgradeable.safeTransferFrom');
 const batch=buildBaselineSequence(erc1155Menu,'ERC1155Upgradeable.safeBatchTransferFrom');
 const approval=buildBaselineSequence(erc1155Menu,'ERC1155Upgradeable.setApprovalForAll');
 assert.deepEqual(single?.steps[1].args,['$account1','$account2','7','7','0x4142']);
 assert.deepEqual(batch?.steps[1].args,['$account1','$account2',['7'],['7'],'0x4142']);
 for(const candidate of [single,batch]){
   assert.deepEqual(candidate?.steps[0].args,['$account2','7']);
   assert.deepEqual(candidate?.steps[2].args,['$account2','7']);
 }
 assert.equal(approval?.steps[0].function,'isApprovedForAll(address,address)');
 assert.deepEqual(approval?.steps[0].args,['$account0','$account1']);
 const {sequenceObservations}=await import('../packages/security-solver/src/source-reproduction');
 assert.equal(sequenceObservations.safeParse({contract:'0x123',accounts:['0','1','2'],
   deploymentGasUsed:'200000',steps:[
     {operation:'observe',function:'balanceOf(address,uint256)',sender:0,actual:'0'},
     {operation:'setup',function:'tomeyMintBatch(address,uint256[],uint256[])',
       sender:0,gasUsed:'50000',passed:true,purpose:'fund transfer prerequisites'},
     {operation:'setup',function:'setApprovalForAll(address,bool)',
       sender:1,gasUsed:'44000',passed:true,purpose:'authorize transfer sender'},
     {operation:'send',function:'safeTransferFrom(address,address,uint256,uint256,bytes)',
       sender:0,valueWei:'0',reverted:false,gasUsed:'31000',passed:true},
     {operation:'observe',function:'balanceOf(address,uint256)',sender:0,actual:'7'}
   ]}).success,true,'Real mined ERC1155 setup receipts must be accepted by the source verifier');
 const adapter=await index.probeMenu(join(root,'contracts/modules/AdapterD008.sol'));
 const adapterSeq=buildBaselineSequence(adapter,'AdapterD008.rotateOperator');
 const dependents=await solidityDependentSources(root,
   'contracts/settlement/SettlementAuthority.sol','SettlementAuthority',
   Object.keys(fixture.files),6);
 assert.ok(dependents.includes('contracts/settlement/SettlementVault.sol'),
   'Controller must inspect Solidity inheritance site after observed role mutation');
 assert.equal(adapterSeq?.steps[0].function,'operator()',
   'A decoy adapter must not use a separately protected settle call as its state observation');
 console.log('Solidity generated getters, state-related transitions and decoy avoidance PASSED');
} finally{await rm(root,{recursive:true,force:true});}
