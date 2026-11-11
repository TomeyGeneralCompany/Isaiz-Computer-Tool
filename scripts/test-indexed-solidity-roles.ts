import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {dirname,join} from 'node:path';
import {tmpdir} from 'node:os';
import {generateCrucible} from './lotus-crucible-generator';
import {privilegedRoleMutationCandidate} from '../packages/security-solver/src/solidity-security-candidates';
import {createProbeSession,replaySourceCase} from '../packages/security-solver/src/source-reproduction';
import {inheritedRoleConsumerImpactSequence,inheritedRoleConsumerImpactObserved} from '../packages/security-solver/src/controller-solidity-consumer-impact';

const root=await mkdtemp(join(tmpdir(),'lotus-verified-solidity-scale-'));
try{
  const c=generateCrucible({language:'solidity',seed:'solidity-controller-indexed-role-20261106'});
  const repo=join(root,'source-1');
  const code=new Map<string,string>();
  for(const [path,body] of Object.entries(c.files)){
    const full=join(repo,path);await mkdir(dirname(full),{recursive:true});
    await writeFile(full,body);
    if(path.endsWith('.sol'))code.set(path,body);
  }
  const baseFile='contracts/settlement/SettlementAuthority.sol';
  const derivedFile='contracts/settlement/SettlementVault.sol';
  const baseSource='pragma solidity ^0.8.20; contract SettlementAuthority { address public operator; constructor(){operator=msg.sender;} function rotateOperator(address next) external {require(next!=address(0),"zero");operator=next;} }';
  const derivedSource='pragma solidity ^0.8.20; import "./SettlementAuthority.sol"; contract SettlementVault is SettlementAuthority { mapping(address=>uint256) public credit; uint256 public totalCredit; function fund(address recipient,uint256 amount) external {credit[recipient]+=amount;totalCredit+=amount;} function settle(address recipient,uint256 amount) external {require(msg.sender==operator,"operator only");require(amount>0&&amount<=totalCredit,"bad amount");credit[recipient]+=amount;totalCredit-=amount;} }';
  for(const [path,source] of [[baseFile,baseSource],[derivedFile,derivedSource]] as const) {
    const full=join(repo,path);await mkdir(dirname(full),{recursive:true});await writeFile(full,source);
  }
  execFileSync('git',['init','-q',repo]);
  execFileSync('git',['-C',repo,'add','.']);
  execFileSync('git',['-C',repo,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','Owned 2000-file Solidity source']);
  const url='https://github.com/fixture/owned';
  const program:any={id:'indexed-solidity-role',provider:'immunefi',name:'Owned indexed Solidity',
    scopeSummary:JSON.stringify({policy:'Owned source only',scopes:[
      {assetType:'SOURCE_CODE',eligibleForBounty:true,assetIdentifier:url}]})};
  const session=await createProbeSession(program,root,[{directory:repo,url}]);
  const observed:string[]=[];
  for(const [file,source] of code){
    const selected=privilegedRoleMutationCandidate(file,source,[source]);
    if(!selected)continue;
    const sequence={constructorArgs:[],steps:[
      {operation:'call' as const,function:selected.role+'()',args:[],expect:'$account0'},
      {operation:'send' as const,function:selected.method+'(address)',args:['$account2'],sender:1},
      {operation:'call' as const,function:selected.role+'()',args:[],expect:'$account2'}
    ]};
    const record=JSON.parse(await session.probe('source-1/'+file,selected.selector,'solidity_sequence',sequence));
    if(record.status!=='behavior_observed')continue;
    assert.match(record.caseId,/^[a-f0-9]{64}$/);
    assert.equal((await replaySourceCase(session.cases.get(record.caseId)!,repo)).behavior_observed,true);
    observed.push(file);
  }
  const inherited=inheritedRoleConsumerImpactSequence(baseSource,derivedSource,
    'operator','rotateOperator',baseFile,derivedFile,'SettlementVault');
  assert.ok(inherited);
  const inheritedResult=JSON.parse(await session.probe('source-1/'+baseFile,
    'SettlementAuthority.rotateOperator','solidity_sequence',inherited));
  assert.equal(inheritedResult.status,'behavior_observed',
    'Actual isolated source verifier must execute the derived consumer contract');
  assert.ok(inheritedRoleConsumerImpactObserved(inheritedResult.observations,'operator','rotateOperator'));
  assert.equal((await replaySourceCase(session.cases.get(inheritedResult.caseId)!,repo)).behavior_observed,true);
  const expected=c.privateAnswerKey.defects.map(d=>d.affectedPaths.at(-1)!).sort();
  assert.deepEqual(observed.sort(),expected,'All five privileged mutations reproduced; no safe controls');
  console.log('2000-file Solidity source-linked nonadministrator EVM role transitions PASSED');
}finally{await rm(root,{recursive:true,force:true});}
