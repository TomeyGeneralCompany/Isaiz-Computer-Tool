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
